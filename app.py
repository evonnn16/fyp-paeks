from flask import Flask, render_template, request, jsonify
import os, json, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import hashlib, base64, time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from Crypto.Util.number import getPrime, getRandomRange

hash2 = hashlib.sha256

def setup():
  #lamda = 'SS512' #symmetric pairing, G1=G2
  #lamda = 'MNT224' #asymmetric pairing, G1!=G2
  lamda = 'BN254' #asymmetric pairing, G1!=G2
  group = PairingGroup(lamda)
  #print(group) #constant

  g1 = group.random(G1)
  #print("g1:",g1)
  g2 = group.random(G2)
  #print("g2:",g2)
  u = pair(g1, g2)
  #print("u:",u)
  params = {'g1':group.serialize(g1),'g2':group.serialize(g2),'u':group.serialize(u)}
  return params

def keygens(params):
  group = PairingGroup('BN254')
  y = group.random(ZR)
  #print("y:",y)
  sk_s = group.serialize(y) #convert object to byte
  #print("sk_s:",group.deserialize(sk_s)) #convert byte to object
  pk_s1 = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** y) #in db store as str, convert to byte then deserialize
  #print("pk_s1:",group.deserialize(pk_s1))
  pk_s2 = group.serialize(group.deserialize(bytes(params['g2'], 'utf-8')) ** y)
  #print("pk_s2:",group.deserialize(pk_s2))
  return [sk_s,pk_s1,pk_s2]

def keygenr(params):
  group = PairingGroup('BN254')
  x = group.random(ZR)
  #print("x:",x)
  sk_r = group.serialize(x)
  #print("sk_r:",group.deserialize(sk_r))
  pk_r = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** x)
  #print("pk_r:",group.deserialize(pk_r))
  return [sk_r,pk_r]

def paeks(params, w, sk_s, pk_r):
  group = PairingGroup('BN254')
  r = group.random(ZR)
  #print("r:",r)
  A = hash2(repr((group.deserialize(bytes(params['u'], 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8')))**r).encode()).hexdigest()
  #print("A:",A)
  temp = group.deserialize(bytes(pk_r, 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8'))
  #print("temp:",temp)
  v = group.hash((w,temp),ZR) #H1
  #print("v:",v)
  B = group.deserialize(bytes(params['g1'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
  #print("B:",B)
  #print("Cw: A:",A," , B:",B)
  return {'A':A, 'B':group.serialize(B)}
  
def trapdoor(params, w2, pk_s1, pk_s2, sk_r):
  group = PairingGroup('BN254')
  temp2 = group.deserialize(bytes(pk_s1, 'utf-8'))**group.deserialize(bytes(sk_r, 'utf-8'))
  v2 = group.hash((w2,temp2),ZR) #H1
  #print("v':",v2)
  Tw = group.deserialize(bytes(pk_s2, 'utf-8'))**(1/(group.deserialize(bytes(sk_r, 'utf-8'))+v2))
  #print("Tw:",Tw)
  return group.serialize(Tw)

def test(Cw, Tw):
  group = PairingGroup('BN254')
  pairing = pair(group.deserialize(Tw),group.deserialize(bytes(Cw['B'], 'utf-8')))
  #print("temp pairing:",pairing)
  lhs = hash2(repr(pairing).encode()).hexdigest()
  #print("lhs:",lhs)
  #print("rhs:",Cw['A'])
  return lhs == Cw['A']

def aes_encrypt(eid, data):
  header = eid.encode('UTF-8')
  #print(header)
  edata = json.dumps({
    'from': data[0]['from'],
    'to': data[0]['to'],
    'subject': data[0]['subject'],
    'content': data[0]['content'],
    'date': data[0]['date']
  }).encode('utf-8')
  #print(edata)
  
  key = get_random_bytes(32)
  c = AES.new(key, AES.MODE_GCM)
  c.update(header)
  ciphertext, tag = c.encrypt_and_digest(edata)
  
  Cm = {
    'nonce': base64.b64encode(c.nonce).decode('utf-8'),
    'header': base64.b64encode(header).decode('utf-8'),
    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
    'tag': base64.b64encode(tag).decode('utf-8')
  }
  #print(f"{type(Cm)} : {Cm}")
  #print(f"{type(json.dumps(Cm))} : {json.dumps(Cm)}")
  return key, Cm

def aes_decrypt(key, Cm):
  c = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(Cm['nonce']))
  c.update(base64.b64decode(Cm['header']))
  m = c.decrypt_and_verify(base64.b64decode(Cm['ciphertext']), base64.b64decode(Cm['tag']))
  #print("The message was: " + m.decode('utf-8'))
  return json.loads(m.decode('utf-8'))

def elgamal_keygen():
  p = getPrime(2048)
  print("p:",p,"-",p.bit_length(),"bits")
  #x = getRandomRange(1, p-2) #sk
  x = randrange(1, p-2)
  print("x:",x,"-",x.bit_length(),"bits")
  #g = getRandomRange(1, p-1) 
  g = randrange(1, p-1)
  print("g:",g,"-",g.bit_length(),"bits")
  y = pow(g, x, p)
  #print("y:",y,"-",y.bit_length(),"bits")
  #pk = {'p':base64.b64encode(str(p).encode()),'g':base64.b64encode(str(g).encode()),'y':base64.b64encode(str(y).encode())} # ElGamal.construct((p, g, y))
  #return {'p':base64.b64encode(str(p).encode()),'x':base64.b64encode(str(x).encode())}, pk
  pk = {'p':p,'g':g,'y':y}
  #sk = {'p':p,'x':x}
  return base64.b64encode(str(x).encode('utf-8')), base64.b64encode(json.dumps(pk).encode('utf-8'))

def elgamal_encrypt(msg, eg_pk):
  pk = json.loads(base64.b64decode(eg_pk).decode('utf-8'))
  m = int.from_bytes(msg, 'big')
  k = randrange(1, int(pk['p'])-2)
  #print("k:",k,"-",k.bit_length(),"bits")

  c1 = pow(int(pk['g']), k, int(pk['p']))
  c2 = m * pow(pk['y'], k, pk['p']) % pk['p']
  #cm = (c1, c2)
  return {'c1':str(c1), 'c2':str(c2)}

def elgamal_decrypt(Ck, sk, pk):
  p = int(json.loads(base64.b64decode(pk).decode('utf-8'))['p'])
  m = int(Ck['c2']) * pow(int(Ck['c1']), p-1-int(base64.b64decode(sk).decode('utf-8')), p) % p
  return m.to_bytes((m.bit_length() + 7) // 8, 'big')


cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
  "databaseURL": "https://fyp-paeks-default-rtdb.asia-southeast1.firebasedatabase.app/"
})

app = Flask(__name__)

@app.route("/") 
def index():
  return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
  data = request.get_json()

  users = db.reference('users/').get()
  if(users != None):
    for u in users:
      if(data[0]['email'] == users[u]["email"]):
        return "email existed"

  #setup global params if not yet in db, if existed proceed to keygen for both sender & receiver
  params = db.reference('params/').get() 
  if(params == None):
    params = setup() 
    db.reference('params/').set({'g1':params['g1'],'g2':params['g2'],'u':params['u']})
    params = db.reference('params/').get()
    
  #print("params:",params)
  [sk_s,pk_s1,pk_s2] = keygens(params)
  [sk_r,pk_r] = keygenr(params)
  
  eg_sk,eg_pk = elgamal_keygen()
  #print(f"after: eg_sk:{base64.b64decode(eg_sk['p']).decode()}")
  #print(f"eg_sk:{eg_sk}\neg_pk:{eg_pk}\nafter:\neg_sk:{int(base64.b64decode(eg_sk).decode('utf-8'))}\neg_pk:{json.loads(base64.b64decode(eg_pk).decode('utf-8'))}")
  
  db.reference('users/').child(str(uuid.uuid4())).set({
    'username': data[0]['username'],
    'email': data[0]['email'],
    'pwd': data[0]['pwd'],
    'sk_s': sk_s,
    'pk_s1': pk_s1,
    'pk_s2': pk_s2,
    'sk_r': sk_r,
    'pk_r': pk_r,
    'eg_sk': eg_sk,
    'eg_pk': eg_pk
  })
  return "success"

@app.route('/login', methods=['GET', 'POST'])
def login():
  data = request.get_json()
  users = db.reference('users/').get()
  for u in users:
    # print(u,":",users[u]["email"])
    if(data[0]['email'] == users[u]["email"] and data[0]['pwd'] == users[u]["pwd"]):
      return "success" #return u
  return "0"

@app.route('/create', methods=['GET', 'POST'])
def insert():
  data = request.get_json()
  
  params = db.reference('params/').get() 
  
  users = db.reference('users/').get()
  for u in users:
    if(data[0]['from'] == users[u]["email"]):
      sk_s = users[u]["sk_s"]
      s = u
      #print(f"s:{s}")
    if(data[0]['to'] == users[u]["email"]):
      pk_r = users[u]["pk_r"]
      eg_pk = users[u]["eg_pk"]
  #print(data[0]['from'],"sk_s:",sk_s)
  #print(data[0]['to'],"pk_r:",pk_r)
  
  if(pk_r == None): return "Receiver's email address not found!"
  
  Cw = paeks(params, data[0]['keyword'], sk_s, pk_r)
  #print("create/Cw:",Cw)
  
  eid = str(uuid.uuid4())
  
  aes_key, Cm = aes_encrypt(eid, data)
  #print(f"aes key: {aes_key}")
  
  Ck = elgamal_encrypt(aes_key, eg_pk)
  #print(f"Ck:{Ck}")
  
  db.reference('emails/').child(eid).set({
    'key': Ck,
    'ciphertext': Cm,
    'keyword': Cw,
    'sender': s
  })
  
  return "Email is sent successfully!"

@app.route('/search', methods=['GET', 'POST'])
def search():
  data = request.get_json()
  #print(data[0]['keyword'])
  
  params = db.reference('params/').get() 
  
  users = db.reference('users/').get()
  for u in users:
    if(data[0]['uid'] == users[u]["email"]):
      sk_r = users[u]["sk_r"]
      eg_sk = users[u]["eg_sk"]
      eg_pk = users[u]["eg_pk"]
      break
  #print(data[0]['uid'],"sk_r:",sk_r)
  
  emails = db.reference('emails/').get()
  received_mails = {}
  if(emails != None):
    for e in emails:
      pk_s1 = users[emails[e]["sender"]]["pk_s1"]
      pk_s2 = users[emails[e]["sender"]]["pk_s2"]
      #print(f"{e}: {users[emails[e]['sender']]['email']}: pk_s1: {pk_s1}, pk_s2: {pk_s2}")
      Tw = trapdoor(params, data[0]['keyword'], pk_s1, pk_s2, sk_r)
      #print(f"trapdoor: {Tw}, keyword: {emails[e]['keyword']}")
      result = test(emails[e]["keyword"],Tw)
      #print(f"test result {e}: {result}")
      if(result):
        key = elgamal_decrypt(emails[e]['key'], eg_sk, eg_pk)
        received_mails[e] = aes_decrypt(key, emails[e]['ciphertext'])
        received_mails[e]["username"] = [users[k]['username'] for k in users if users[k]['email'] == received_mails[e]["from"]][0]
  
    
  print(f"search result:{received_mails}")
  
  return jsonify(received_mails)

@app.route('/view', methods=['GET', 'POST'])
def view():
  eid = request.get_json()
  emails = db.reference('emails/')
  mail_list = emails.get()
  print(mail_list[eid])
  return jsonify(mail_list[eid])

@app.route('/profile', methods=['GET', 'POST'])
def profile():
  email = request.get_json()
  users = db.reference('users/')
  user_list = users.get()
  found = {}
  for u in user_list:
    if(email == user_list[u]["email"]):
      found = user_list[u]
      break

  return jsonify(found)

if __name__ == "__main__":
  app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)

# @app.route("/test") 
# app.run(host="127.0.0.1", port=8080, debug=True)
# Running on http://127.0.0.1:8080/test http://localhost:8080/test

# @app.route("/") 
# app.run()
# Running on http://localhost:5000/ http://localhost:8080/
