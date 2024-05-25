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
import numpy as np 

hash2 = hashlib.sha256

def setup(lamda, group):
  #lamda = 'SS512' #symmetric pairing, G1=G2, 80-bits security
  #lamda = 'SS1024' #symmetric pairing, G1=G2, 112-bits security
  #lamda = 'BN254' #asymmetric pairing, G1!=G2, 128-bits security
  #group = PairingGroup(lamda)
  #print(f"curve:{lamda},group:{group}")

  if(lamda == 'BN254'):
    g1 = group.random(G1)
    g2 = group.random(G2)
    u = pair(g1, g2)
    #print(f"g1:{g1}\ng2:{g2}\nu:{u}")
    params = {'g1':group.serialize(g1),'g2':group.serialize(g2),'u':group.serialize(u)}
  elif(lamda == 'SS1024'):
    g = group.random(G1)
    u = pair(g, g)
    #print(f"g:{g}\nu:{u}")
    params = {'g':group.serialize(g),'u':group.serialize(u)}
  return params

def keygens(lamda, group, params):
  #group = PairingGroup(lamda)
  y = group.random(ZR)
  #print("sk_s:",y)
  sk_s = group.serialize(y) #convert object to byte
  #print("sk_s:",group.deserialize(sk_s)) #convert byte to object
  
  if(lamda == 'BN254'):
    #print(f"g1 byte:{params['g1']}\ng1 str:{params['g1'].decode('utf-8')}\ng1 pairing element:{group.deserialize(params['g1'])}\ng1 convert:{group.deserialize(bytes(params['g1'].decode('utf-8'), 'utf-8'))}")
    pk_s1 = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** y) #in db store as str, convert to byte then deserialize
    pk_s2 = group.serialize(group.deserialize(bytes(params['g2'], 'utf-8')) ** y)
    #print("pk_s2:",group.deserialize(pk_s2))
    return [sk_s,pk_s1,pk_s2]
  elif(lamda == 'SS1024'):
    pk_s = group.serialize(group.deserialize(bytes(params['g'], 'utf-8')) ** y)
    #print(f"pk_s:{group.deserialize(pk_s)}")
    return [sk_s,pk_s]

def keygenr(lamda, group, params):
  #group = PairingGroup(lamda)
  x = group.random(ZR)
  #print("sk_r:",x)
  sk_r = group.serialize(x)
  #print("sk_r:",group.deserialize(sk_r))
  
  if(lamda == 'BN254'):
    pk_r = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** x)
    #print("pk_r:",group.deserialize(pk_r))
  elif(lamda == 'SS1024'):
    pk_r = group.serialize(group.deserialize(bytes(params['g'], 'utf-8')) ** x)
    #print("pk_r:",group.deserialize(pk_r))
  return [sk_r,pk_r]

def paeks(lamda, group, params, w, sk_s, pk_r):
  '''start_time = time.time()
  group = PairingGroup(lamda)
  end_time = time.time()
  print("1. time taken:",(end_time - start_time) * 1000)'''
  
  #start_time = time.time()
  r = group.random(ZR)
  #print("r:",r)
  #end_time = time.time()
  #print("1. time taken:",(end_time - start_time) * 1000)
  
  #start_time = time.time()
  temp = (group.deserialize(bytes(params['u'], 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8')))**r
  #end_time = time.time()
  #print("u^yr:",temp)
  #print("2. time taken:",(end_time - start_time) * 1000)
  
  #start_time = time.time()
  A = hash2(repr(temp).encode()).hexdigest()
  #print("A:",type(A))
  #end_time = time.time()
  #print("2. time taken:",(end_time - start_time) * 1000)
  
  #start_time = time.time()
  temp = group.deserialize(bytes(pk_r, 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8'))
  #print("temp:",temp)
  #end_time = time.time()
  #print("3. time taken:",(end_time - start_time) * 1000)
  
  #start_time = time.time()
  v = group.hash((w,temp),ZR) #H1
  #print("v:",v)
  #end_time = time.time()
  #print("4. time taken:",(end_time - start_time) * 1000)  
  
  #start_time = time.time()
  if(lamda == 'BN254'):
    B = group.deserialize(bytes(params['g1'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
  elif(lamda == 'SS1024'):
    B = group.deserialize(bytes(params['g'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
    #print("B:",B)
    #print("Cw: A:",A," , B:",B)
  #end_time = time.time()
  #print("5. time taken:",(end_time - start_time) * 1000)  
  return {'A':str(A), 'B':group.serialize(B)}
  
def trapdoor(lamda, group, params, w2, pk_s1, pk_s2, sk_r):
  #group = PairingGroup(lamda)
  
  if(lamda == 'BN254'):
    temp2 = group.deserialize(bytes(pk_s1, 'utf-8'))**group.deserialize(bytes(sk_r, 'utf-8'))
    v2 = group.hash((w2,temp2),ZR) #H1
    #print("v':",v2)
    Tw = group.deserialize(bytes(pk_s2, 'utf-8'))**(1/(group.deserialize(bytes(sk_r, 'utf-8'))+v2))
  elif(lamda == 'SS1024'):
    #print(f"sk_r:{type(group.deserialize(sk_r))},{group.deserialize(sk_r)},pk_s:{type(group.deserialize(pk_s1))},{group.deserialize(pk_s1)}")
    temp2 = group.deserialize(pk_s1)**group.deserialize(sk_r)
    v2 = group.hash((w2,temp2),ZR) #H1
    #print("v':",v2)
    Tw = group.deserialize(pk_s1)**(1/(group.deserialize(sk_r)+v2))
    #print("Tw:",Tw)
  return group.serialize(Tw)

def test(lamda, group, Cw, Tw):
  try:
    #group = PairingGroup(lamda)
    
    if(lamda == 'BN254'):
      pairing = pair(group.deserialize(Tw),group.deserialize(bytes(Cw['B'], 'utf-8')))
    elif(lamda == 'SS1024'):
      pairing = pair(group.deserialize(Tw),group.deserialize(Cw['B']))
    lhs = hash2(repr(pairing).encode()).hexdigest()
    #print("lhs:",lhs)
    #print("rhs:",Cw['A'])
    return lhs == Cw['A']
  except Exception as e:
    print(f"Error in Test function: {e}")
    return False

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

def perf_paeks(lamda):
  print(f"\n{lamda} PAEKS running...")
  group = PairingGroup(lamda)
  
  print("\nSetup...")
  start_time = time.time()
  params = setup(lamda, group)
  end_time = time.time()
  setup_time = (end_time - start_time) * 1000
  #print("params:",params)
  print("setup time taken:",setup_time)
  
  if(lamda == 'SS1024'):
    params['g'] = params['g'].decode('utf-8')
  elif(lamda == 'BN254'):
    params['g1'] = params['g1'].decode('utf-8')
    params['g2'] = params['g2'].decode('utf-8')  
  params['u'] = params['u'].decode('utf-8')
  
  print("\nKeyGen...")
  if(lamda == 'SS1024'):
    start_time = time.time()
    [sk_s,pk_s] = keygens(lamda, group, params)
    end_time = time.time()
  elif(lamda == 'BN254'):
    start_time = time.time()
    [sk_s,pk_s1,pk_s2] = keygens(lamda, group, params)
    end_time = time.time()
  keygens_time = (end_time - start_time) * 1000
  print("keygens time taken:",keygens_time)
  
  start_time = time.time()
  [sk_r,pk_r] = keygenr(lamda, group, params)
  end_time = time.time()
  keygenr_time = (end_time - start_time) * 1000
  print("keygenr time taken:",keygenr_time)
  
  #print(f"sk_s:{sk_s}\npk_s:{pk_s}\nsk_r:{sk_r}\npk_r:{pk_r}")
  #pk_size = sys.getsizeof(pk_r)*8
  #print(f"pk size:{pk_size}")
  
  keyword = "meeting"
  
  print("\nPAEKS...")
  start_time = time.time()
  Cw = paeks(lamda, group, params, keyword, sk_s.decode('utf-8'), pk_r.decode('utf-8'))
  end_time = time.time()
  paeks_time = (end_time - start_time) * 1000
  cw_size = sys.getsizeof(Cw)*8
  
  #print("Cw:",Cw)
  print("paeks time taken:",paeks_time)
  print("Cw size:",cw_size)
  
  if(lamda == 'BN254'):
    Cw['B'] = Cw['B'].decode('utf-8')
  
  skeyword = "meeting"
  
  print("\nTrapdoor...")
  if(lamda == 'SS1024'):
    start_time = time.time()
    Tw = trapdoor(lamda, group, params, skeyword, pk_s, "", sk_r)
    end_time = time.time()
  elif(lamda == 'BN254'):
    start_time = time.time()
    Tw = trapdoor(lamda, group, params, skeyword, pk_s1.decode('utf-8'), pk_s2.decode('utf-8'), sk_r.decode('utf-8'))
    end_time = time.time()
  #print(f"trapdoor: {Tw}")
  trapdoor_time = (end_time - start_time) * 1000
  print("trapdoor time taken:",trapdoor_time)
  tw_size = sys.getsizeof(Tw)*8
  print("Tw size:",tw_size)
  
  print("\nTest...")
  start_time = time.time()
  result = test(lamda, group, Cw, Tw)
  end_time = time.time()
  print(f"test result: {result}")
  test_time = (end_time - start_time) * 1000
  print("test time taken:",test_time)
  
  '''xpt = ["Setup","KeyGenS","KeyGenR","PAEKS","Trapdoor","Test"]
  ypt = [setup_time,keygens_time,keygenr_time,paeks_time,trapdoor_time,test_time]
  plt.title("Algorithms Execution Time")
  plt.ylabel("Time (ms)")
  plt.bar(xpt,ypt)
  plt.show()
  
  xpt = ["Public Key","Ciphertext","Trapdoor"]
  ypt = [pk_size,cw_size,tw_size]
  plt.bar(xpt,ypt)
  plt.title("Communication Cost")
  plt.ylabel("Size (bits)")
  plt.show()'''
  
  return [setup_time,keygens_time,keygenr_time,paeks_time,trapdoor_time,test_time,paeks_time+trapdoor_time+test_time]

def graph(data1, data2):  
  plt.figure(num="PAEKS Performance Analysis")
  
  '''data = db.reference('performance/time/').get()
  xpt = ["PAEKS","Trapdoor","Test"]
  ypt = [data["paeks"]["sum"]/data["paeks"]["count"]*1000, data["trapdoor"]["sum"]/data["trapdoor"]["count"]*1000, data["test"]["sum"]/data["test"]["count"]*1000]
  plt.title("Algorithms Average Execution Time")
  plt.ylabel("Average Time (ms)")
  plt.bar(xpt,ypt)
  plt.show()'''
  
  '''data = db.reference('performance/size/').get()
  xpt = ["Ciphertext","Trapdoor"]
  ypt = [data["paeks"]["sum"]/data["paeks"]["count"], data["trapdoor"]["sum"]/data["trapdoor"]["count"]]
  plt.bar(xpt,ypt)
  plt.title("Average Communication Cost")
  plt.ylabel("Size (bits)")
  plt.show()'''
  
  x = ["Setup","KeyGenS","KeyGenR","PAEKS","Trapdoor","Test","Total"]
  xaxis = np.arange(len(x))
  plt.bar(xaxis - 0.2, data1, 0.4, label = 'Type 1')
  plt.bar(xaxis + 0.2, data2, 0.4, label = 'Type 3')
  plt.xticks(xaxis, x)
  plt.ylabel("Time (ms)")
  plt.title("Algorithms Execution Time")
  plt.legend()
  plt.show()

if __name__ == "__main__":
  type1 = perf_paeks('SS1024')
  type3 = perf_paeks('BN254')
  graph(type1, type3)
  #app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)

