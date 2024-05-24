from flask import Flask, render_template, request, jsonify
import sys, os, json, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import hashlib, base64, secrets, time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from Crypto.Util.number import getPrime, getRandomRange
import matplotlib.pyplot as plt

hash2 = hashlib.sha256

def setup(lamda):
  #lamda = 'SS512' #symmetric pairing, G1=G2
  #lamda = 'MNT224' #asymmetric pairing, G1!=G2
  #lamda = 'BN254' #asymmetric pairing, G1!=G2
  group = PairingGroup(lamda)

  if(lamda == 'BN254'):
    g1 = group.random(G1)
    g2 = group.random(G2)
    u = pair(g1, g2)
    params = {'g1':group.serialize(g1),'g2':group.serialize(g2),'u':group.serialize(u)}
  elif(lamda == 'SS512'):
    g1 = group.random(G1)
    u = pair(g1, g1)
    params = {'g':str(group.serialize(g1)),'u':str(group.serialize(u))}
  return params

def keygens(lamda, params):
  group = PairingGroup(lamda)
  y = group.random(ZR)
  #print("y:",y)
  sk_s = group.serialize(y) #convert object to byte
  #print("sk_s:",group.deserialize(sk_s)) #convert byte to object
  
  if(lamda == 'BN254'):
    pk_s1 = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** y) #in db store as str, convert to byte then deserialize
    #print("pk_s1:",group.deserialize(pk_s1))
    pk_s2 = group.serialize(group.deserialize(bytes(params['g2'], 'utf-8')) ** y)
    #print("pk_s2:",group.deserialize(pk_s2))
    return [sk_s,pk_s1,pk_s2]
  elif(lamda == 'SS512'):
    pk_s = group.serialize(group.deserialize(bytes(params['g'], 'utf-8')) ** y)
    return [str(sk_s),str(pk_s)]

def keygenr(lamda, params):
  group = PairingGroup(lamda)
  x = group.random(ZR)
  #print("x:",x)
  sk_r = group.serialize(x)
  #print("sk_r:",group.deserialize(sk_r))
  
  if(lamda == 'BN254'):
    pk_r = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** x)
    #print("pk_r:",group.deserialize(pk_r))
  elif(lamda == 'SS512'):
    pk_r = group.serialize(group.deserialize(bytes(params['g'], 'utf-8')) ** x)
  return [str(sk_r),str(pk_r)]

def paeks(lamda, params, w, sk_s, pk_r):
  group = PairingGroup(lamda)
  r = group.random(ZR)
  #print("r:",r)
  A = hash2(repr((group.deserialize(bytes(params['u'], 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8')))**r).encode()).hexdigest()
  #print("A:",A)
  temp = group.deserialize(bytes(pk_r, 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8'))
  #print("temp:",temp)
  v = group.hash((w,temp),ZR) #H1
  #print("v:",v)
  
  if(lamda == 'BN254'):
    B = group.deserialize(bytes(params['g1'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
  elif(lamda == 'SS512'):
    B = group.deserialize(bytes(params['g'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
  #print("B:",B)
  #print("Cw: A:",A," , B:",B)
  return {'A':str(A), 'B':str(group.serialize(B))}
  
def trapdoor(lamda, params, w2, pk_s1, pk_s2, sk_r):
  group = PairingGroup(lamda)
  
  temp2 = group.deserialize(bytes(pk_s1, 'utf-8'))**group.deserialize(bytes(sk_r, 'utf-8'))
  v2 = group.hash((w2,temp2),ZR) #H1
  #print("v':",v2)
  
  if(lamda == 'BN254'):
    Tw = group.deserialize(bytes(pk_s2, 'utf-8'))**(1/(group.deserialize(bytes(sk_r, 'utf-8'))+v2))
    #print("Tw:",Tw)
  elif(lamda == 'SS512'):
    Tw = group.deserialize(bytes(pk_s1, 'utf-8'))**(1/(group.deserialize(bytes(sk_r, 'utf-8'))+v2))
  return group.serialize(Tw)

def test(lamda, Cw, Tw):
  group = PairingGroup(lamda)
  B = group.deserialize(bytes(Cw['B'], 'utf-8'))
  print("test:",B)
  pairing = pair(group.deserialize(Tw),B)
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

def hashing_pwd(pwd):
  salt = secrets.token_bytes(16)
  h = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, 100000)
  return base64.b64encode(salt), base64.b64encode(h)

def verify_pwd(uhash, salt, pwd):
  h = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), base64.b64decode(salt), 100000)
  return base64.b64decode(uhash) == h

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
    params = setup('BN254') 
    db.reference('params/').set({'g1':params['g1'],'g2':params['g2'],'u':params['u']})
    params = db.reference('params/').get()
    
  #print("params:",params)
  [sk_s,pk_s1,pk_s2] = keygens('BN254',params)
  [sk_r,pk_r] = keygenr('BN254',params)
  
  eg_sk,eg_pk = elgamal_keygen()
  #print(f"after: eg_sk:{base64.b64decode(eg_sk['p']).decode()}")
  #print(f"eg_sk:{eg_sk}\neg_pk:{eg_pk}\nafter:\neg_sk:{int(base64.b64decode(eg_sk).decode('utf-8'))}\neg_pk:{json.loads(base64.b64decode(eg_pk).decode('utf-8'))}")
  
  salt, pwd_hash = hashing_pwd(data[0]['pwd'])
  
  db.reference('users/').child(str(uuid.uuid4())).set({
    'username': data[0]['username'],
    'email': data[0]['email'],
    'sk_s': sk_s,
    'pk_s1': pk_s1,
    'pk_s2': pk_s2,
    'sk_r': sk_r,
    'pk_r': pk_r,
    'eg_sk': eg_sk,
    'eg_pk': eg_pk,
    'salt': salt,
    'hash': pwd_hash
  })
  return "success"

@app.route('/login', methods=['GET', 'POST'])
def login():
  data = request.get_json()
  users = db.reference('users/').get()
  
  for u in users:
    # print(u,":",users[u]["email"])
    if(data[0]['email'] == users[u]["email"]):
      if(verify_pwd(users[u]["hash"],users[u]["salt"],data[0]['pwd'])):
        return {"status": "success", "uid": u}
  return {"status": "error", "msg": "account not found or password is wrong"}

@app.route('/create', methods=['GET', 'POST'])
def insert():
  data = request.get_json()
  #print(data[0]['content'])
  
  params = db.reference('params/').get() 
  
  users = db.reference('users/').get()
  
  s = data[0]['from']
  data[0]['from'] = users[s]["email"]
  sk_s = users[s]["sk_s"]
  #print(f"s:{s}, sk_s:{sk_s}")
  
  pk_r = None
  for u in users:      
    if(data[0]['to'] == users[u]["email"]):
      pk_r = users[u]["pk_r"]
      eg_pk = users[u]["eg_pk"]
      r = u
  #print(data[0]['to'],"pk_r:",pk_r)
  
  if(pk_r == None): return "Receiver's email address not found!"
  
  keyword = data[0]['keyword'].split(' ')
  keyword.sort()
  #print(keyword)
  
  start_time = time.time()
  Cw = paeks('BN254',params, str(keyword), sk_s, pk_r)
  #print("Cw:",Cw)
  end_time = time.time()
  paeks_time = end_time - start_time # f"{end_time - start_time:.6f}"
  #print("paeks time taken:",paeks_time)
  cw_size = sys.getsizeof(Cw)*8
  
  eid = str(uuid.uuid4())
  
  aes_key, Cm = aes_encrypt(eid, data)
  #print(f"aes key: {aes_key}")
  
  Ck = elgamal_encrypt(aes_key, eg_pk)
  #print(f"Ck:{Ck}")
  
  db.reference('emails/').child(r).child(s).child(eid).set({
    'key': Ck,
    'ciphertext': Cm,
    'keyword': Cw
  })
  
  perf = db.reference('performance/time/paeks/')
  if(perf.get() == None):
    perf.set({"sum":paeks_time,"count":1})
    #print("first time insert:",paeks_time)
  else:
    perf.set({"sum":perf.get()["sum"] + paeks_time,"count":perf.get()["count"]+1})
    
  perf = db.reference('performance/size/paeks/')
  if(perf.get() == None):
    perf.set({"sum":cw_size,"count":1})
    #print("first time insert:",cw_size)
  else:
    perf.set({"sum":perf.get()["sum"] + cw_size,"count":perf.get()["count"]+1})
  
  return "Email is sent successfully!"

@app.route('/search', methods=['GET', 'POST'])
def search():
  data = request.get_json()
  
  params = db.reference('params/').get() 
  
  users = db.reference('users/').get()
  r = data[0]['uid']
  sk_r = users[r]["sk_r"]
  eg_sk = users[r]["eg_sk"]
  eg_pk = users[r]["eg_pk"]
  
  keyword = data[0]['keyword'].split(' ')
  keyword.sort()
  #print(keyword)
  
  emails = db.reference('emails/').child(r).get()
  received_mails = {}
  if(emails != None):
    for s in emails:
      pk_s1 = users[s]["pk_s1"]
      pk_s2 = users[s]["pk_s2"]
      #print(f"{s}: {users[s]['email']}: pk_s1: {pk_s1}, pk_s2: {pk_s2}")
      
      start_time = time.time()
      Tw = trapdoor('BN254', params, str(keyword), pk_s1, pk_s2, sk_r)
      #print(f"trapdoor: {Tw}")
      end_time = time.time()
      trapdoor_time = end_time - start_time # f"{end_time - start_time:.6f}"
      #print("trapdoor time taken:",trapdoor_time)
      tw_size = sys.getsizeof(Tw)*8
      
      for e in emails[s]:
        start_time = time.time()
        result = test('BN254', emails[s][e]["keyword"],Tw)
        #print(f"test result {e}: {result}")
        end_time = time.time()
        test_time = end_time - start_time
        #print("test time taken:",test_time)
        
        if(result):
          key = elgamal_decrypt(emails[s][e]['key'], eg_sk, eg_pk)
          received_mails[e] = aes_decrypt(key, emails[s][e]['ciphertext'])
          #print(received_mails[e])
          received_mails[e]["username"] = [users[k]['username'] for k in users if users[k]['email'] == received_mails[e]["from"]][0]
        
        perf = db.reference('performance/time/test/')
        if(perf.get() == None): perf.set({"sum":test_time,"count":1})
        else: perf.set({"sum":perf.get()["sum"] + test_time,"count":perf.get()["count"]+1})
      
      perf = db.reference('performance/time/trapdoor/')
      if(perf.get() == None): perf.set({"sum":trapdoor_time,"count":1})
      else: perf.set({"sum":perf.get()["sum"] + trapdoor_time,"count":perf.get()["count"]+1})
      
      perf = db.reference('performance/size/trapdoor/')
      if(perf.get() == None): perf.set({"sum":tw_size,"count":1})
      else: perf.set({"sum":perf.get()["sum"] + tw_size,"count":perf.get()["count"]+1})
  
  #print(f"search result:{received_mails}")
  
  return jsonify(received_mails)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
  uid = request.get_json()
  u = db.reference('users/').child(uid).get()
  return {"status":"success","username":u["username"],"email":u["email"]}

def type1_paeks():
  print("Type 1 PAEKS running")
  params = setup('SS512')
  
  [sk_s,pk_s] = keygens('SS512',params)
  [sk_r,pk_r] = keygenr('SS512',params)
  
  keyword = "meeting"
  
  start_time = time.time()
  Cw = paeks('SS512', params, keyword, sk_s, pk_r)
  end_time = time.time()
  paeks_time = (end_time - start_time) * 1000
  cw_size = sys.getsizeof(Cw)*8
  
  print("params:",params)
  print(f"sk_s:{sk_s}\npk_s:{pk_s}\nsk_r:{sk_r}\npk_r:{pk_r}")
  print("Cw:",Cw)
  print("paeks time taken:",paeks_time)
  print("Cw size:",cw_size)
  
  skeyword = "meeting"
  
  start_time = time.time()
  Tw = trapdoor('SS512', params, skeyword, pk_s, "", sk_r)
  end_time = time.time()
  print(f"trapdoor: {Tw}")
  trapdoor_time = (end_time - start_time) * 1000
  print("trapdoor time taken:",trapdoor_time)
  tw_size = sys.getsizeof(Tw)*8
  
  start_time = time.time()
  result = test('SS512', Cw, Tw)
  end_time = time.time()
  print(f"test result: {result}")
  test_time = (end_time - start_time) * 1000
  print("test time taken:",test_time)

def graph():  
  plt.figure(num="PAEKS Performance Analysis")
  
  data = db.reference('performance/time/').get()
  xpt = ["PAEKS","Trapdoor","Test"]
  ypt = [data["paeks"]["sum"]/data["paeks"]["count"]*1000, data["trapdoor"]["sum"]/data["trapdoor"]["count"]*1000, data["test"]["sum"]/data["test"]["count"]*1000]
  plt.title("Algorithms Average Execution Time")
  plt.ylabel("Average Time (ms)")
  plt.bar(xpt,ypt)
  plt.show()
  
  '''data = db.reference('performance/size/').get()
  xpt = ["Ciphertext","Trapdoor"]
  ypt = [data["paeks"]["sum"]/data["paeks"]["count"], data["trapdoor"]["sum"]/data["trapdoor"]["count"]]
  plt.bar(xpt,ypt)
  plt.title("Average Communication Cost")
  plt.ylabel("Size (bits)")
  plt.show()'''

if __name__ == "__main__":
  type1_paeks()
  #graph()
  #app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)

