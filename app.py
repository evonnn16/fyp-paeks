from flask import Flask, render_template, request, jsonify
import sys, os, json, re, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import hashlib, base64, secrets, time
from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import numpy as np 
from datetime import datetime

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
  "databaseURL": "https://fyp-paeks-default-rtdb.asia-southeast1.firebasedatabase.app/"
})

app = Flask(__name__)

def measure_time(func):
  def wrapper(*args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    execution_time = (end_time - start_time) * 1000
    return result, execution_time
  return wrapper
    
class PAEKS:
  def __init__(self, pairing_type, group):
    self.pairing_type = pairing_type
    self.group = group
    self.hash2 = hashlib.sha256
    
    if(pairing_type == 'type3'):
      self.g1 = group.random(G1)
      self.g2 = group.random(G2)
      self.u = pair(self.g1, self.g2)
    elif(pairing_type == 'type1'):
      self.g = group.random(G1)
      self.u = pair(self.g, self.g)
  
  @measure_time
  def keygens(self):
    self.sk_s = self.group.random(ZR)
    
    if(self.pairing_type == 'type3'):
      self.pk_s1 = self.g1 ** self.sk_s
      self.pk_s2 = self.g2 ** self.sk_s
    elif(self.pairing_type == 'type1'):
      self.pk_s = self.g ** self.sk_s
  
  @measure_time
  def keygenr(self):
    self.sk_r = self.group.random(ZR)
    
    if(self.pairing_type == 'type3'):
      self.pk_r = self.g1 ** self.sk_r
    elif(self.pairing_type == 'type1'):
      self.pk_r = self.g ** self.sk_r
  
  @measure_time
  def encrypt(self, w):
    r = self.group.random(ZR)
    A = self.hash2(repr((self.u ** self.sk_s) ** r).encode()).digest()
    v = self.group.hash((w, self.pk_r ** self.sk_s),ZR)
  
    if(self.pairing_type == 'type3'):
      B = self.g1**(v*r) * self.pk_r**r
    elif(self.pairing_type == 'type1'):
      B = self.g**(v*r) * self.pk_r**r
    return {'A':A, 'B':B}
  
  @measure_time
  def trapdoor(self, w2):
    if(self.pairing_type == 'type3'):
      v2 = self.group.hash((w2, self.pk_s1 ** self.sk_r),ZR)
      Tw = self.pk_s2**(1/(self.sk_r + v2))
    elif(self.pairing_type == 'type1'):
      v2 = self.group.hash((w2, self.pk_s ** self.sk_r),ZR)
      Tw = self.pk_s**(1/(self.sk_r + v2))
    return Tw
  
  @measure_time
  def test(self, Cw, Tw):
    pairing = pair(Tw, Cw['B'])
    lhs = self.hash2(repr(pairing).encode()).digest()
    if(self.pairing_type == 'type3'):
      lhs = adjust_hash_size(lhs, 254)
    elif(self.pairing_type == 'type1'):
      lhs = adjust_hash_size(lhs, 1024)
    return lhs == Cw['A']
  
  def paekstobyte(self, paeks_obj):
    return self.group.serialize(paeks_obj)
  
  def strtopaeks(self, string_obj):
    return self.group.deserialize(bytes(string_obj, 'utf-8'))

@measure_time
def aes_enc(key, eid, data):
  header = eid.encode('UTF-8')
  edata = json.dumps({
    'from': data[0]['from'],
    'to': data[0]['to'],
    'subject': data[0]['subject'],
    'content': data[0]['content'],
    'date': data[0]['date']
  }).encode('utf-8')
  
  c = AES.new(key, AES.MODE_GCM)
  c.update(header)
  ciphertext, tag = c.encrypt_and_digest(edata)
  
  Cm = {
    'nonce': base64.b64encode(c.nonce).decode('utf-8'),
    'header': base64.b64encode(header).decode('utf-8'),
    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
    'tag': base64.b64encode(tag).decode('utf-8')
  }
  return Cm

@measure_time
def aes_dec(key, Cm):
  c = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(Cm['nonce']))
  c.update(base64.b64decode(Cm['header']))
  m = c.decrypt_and_verify(base64.b64decode(Cm['ciphertext']), base64.b64decode(Cm['tag']))
  return json.loads(m.decode('utf-8'))

@measure_time
def elgamal_enc(group, msg, pk):
  k = group.random(ZR)
  c1 = pk['g'] ** k
  c2 = msg * (pk['y'] ** k)
  return {'c1': c1, 'c2': c2}

@measure_time
def elgamal_dec(self, Ck, sk):
  m = Ck['c2'] / (Ck['c1'] ** sk)
  return m

def hashing_pwd(pwd):
  salt = secrets.token_bytes(16)
  h = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, 100000)
  return base64.b64encode(salt), base64.b64encode(h)

def verify_pwd(uhash, salt, pwd):
  h = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), base64.b64decode(salt), 100000)
  return base64.b64decode(uhash) == h

def calc_size(data, data_type):
  if data_type == 'Cm':
    return len(base64.b64decode(data['nonce']))*8 + len(base64.b64decode(data['header']))*8 + len(base64.b64decode(data['tag']))*8 + len(base64.b64decode(data['ciphertext']))*8
  elif data_type == 'g':    
    bsize = [int(i) for i in re.findall(r'\d+', str(data))]
    return sum(len(bin(i))-2 for i in bsize)
  elif data_type == 'm':
    return len(json.dumps(data).encode('utf-8'))*8

def adjust_hash_size(data, size):
  binstr = ''.join(format(byte, '08b') for byte in data)
  return binstr[:size].ljust(size, '0')

@app.route("/") 
def index():
  return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
  data = request.get_json()
  
  global paeks

  users = db.reference('users/').get()
  if(users != None):
    for u in users:
      if(data[0]['email'] == users[u]["email"]):
        return {"status":"fail","msg":"Email address existed"}
  
  result, keygens_time = paeks.keygens()
  result, keygenr_time = paeks.keygenr()
  print(f"keygens time: {keygens_time} ms\nkeygenr time: {keygenr_time} ms")
  
  salt, pwd_hash = hashing_pwd(data[0]['pwd'])
  
  db.reference('users/').child(str(uuid.uuid4())).set({
    'username': data[0]['username'],
    'email': data[0]['email'],
    'sk_s': paeks.paekstobyte(paeks.sk_s),
    'pk_s1': paeks.paekstobyte(paeks.pk_s1),
    'pk_s2': paeks.paekstobyte(paeks.pk_s2),
    'sk_r': paeks.paekstobyte(paeks.sk_r),
    'pk_r': paeks.paekstobyte(paeks.pk_r),
    'salt': salt,
    'hash': pwd_hash
  })
  return {"status":"success","msg":"Account successfully created"}

@app.route('/login', methods=['GET', 'POST'])
def login():
  data = request.get_json()
  users = db.reference('users/').get()
  
  if users is None: return {"status": "fail", "msg": "Account is not found or password is wrong"}
  else:
    for u in users:
      if(data[0]['email'] == users[u]["email"]):
        if(verify_pwd(users[u]["hash"],users[u]["salt"],data[0]['pwd'])):
          return {"status": "success", "uid": u}
    else: return {"status": "fail", "msg": "Account is not found or password is wrong"}

@app.route('/create', methods=['GET', 'POST'])
def insert():
  data = request.get_json()
  
  global paeks
  
  users = db.reference('users/').get()
  
  s = data[0]['from']
  data[0]['from'] = users[s]["email"]
  paeks.sk_s = paeks.strtopaeks(users[s]["sk_s"])
  
  for u in users:      
    if(data[0]['to'] == users[u]["email"]):
      paeks.pk_r = paeks.strtopaeks(users[u]["pk_r"])
      r = u
      break
  else: return {"status":"fail","msg":"Receiver's email address not found"}
  
  keyword = [word.lower() for word in data[0]['keyword'].split(' ')]
  
  Cw = []
  
  for i in keyword:
    cw, paeks_time = paeks.encrypt(i)
    cw['A'] = adjust_hash_size(cw['A'], 254)
    cw_size = calc_size(cw['B'], 'g') + len(cw['A'])
    cw['B'] = paeks.paekstobyte(cw['B'])
    print(f"PAEKS time taken: {paeks_time} ms")
    print(f"Cw size: {cw_size} bits")
    Cw.append(cw)
  
  eid = str(uuid.uuid4())
  
  aes_key = group.random(G1)
  Cm, aes_enc_time = aes_enc(paeks.paekstobyte(aes_key)[:32], eid, data)
  print(f"AES enc time: {aes_enc_time} ms")
  cm_size = calc_size(Cm, 'Cm')
  print(f"Cm size: {cm_size} bits")
  
  eg_pk = {'g': paeks.g1, 'y': paeks.pk_r}
  Ck, elgamal_enc_time = elgamal_enc(paeks.group, aes_key, eg_pk)
  ck_size = calc_size(Ck['c1'], 'g') + calc_size(Ck['c2'], 'g')
  Ck['c1'] = paeks.paekstobyte(Ck['c1'])
  Ck['c2'] = paeks.paekstobyte(Ck['c2'])
  print(f"ElGamal enc time: {elgamal_enc_time} ms")
  print(f"Ck size: {ck_size} bits")
  
  db.reference('emails/').child(r).child(s).child(eid).set({
    'key': Ck,
    'ciphertext': Cm,
    'keyword': Cw
  })
  
  return {"status": "success", "msg":"Email is sent successfully!"}

@app.route('/search', methods=['GET', 'POST'])
def search():
  data = request.get_json()
  
  global paeks
  
  users = db.reference('users/').get()
  r = data[0]['uid']
  paeks.sk_r = paeks.strtopaeks(users[r]["sk_r"])
  
  keyword = [word.lower() for word in data[0]['keyword'].split(' ')]
  
  emails = db.reference('emails/').child(r).get()
  received_mails = {}
  if(emails != None):
    for s in emails:
      paeks.pk_s1 = paeks.strtopaeks(users[s]["pk_s1"])
      paeks.pk_s2 = paeks.strtopaeks(users[s]["pk_s2"])
      
      for w in keyword:
        Tw, trapdoor_time = paeks.trapdoor(w)
        print(f"Trapdoor time taken: {trapdoor_time} ms")
        tw_size = calc_size(Tw, 'g')
        print(f"Tw size: {tw_size} bits")
        
        for e in emails[s]:
          for k in emails[s][e]['keyword']:
            if isinstance(k['B'], str): k['B'] = paeks.strtopaeks(k['B'])
            result, test_time = paeks.test(k,Tw)
            print(f"Test time taken: {test_time} ms")
          
            if(result):
              if isinstance(emails[s][e]['key']['c1'], str): 
                emails[s][e]['key']['c1'] = paeks.strtopaeks(emails[s][e]['key']['c1'])
                emails[s][e]['key']['c2'] = paeks.strtopaeks(emails[s][e]['key']['c2'])
              key, elgamal_dec_time = elgamal_dec(paeks.group, emails[s][e]['key'], paeks.sk_r)
              print(f"ElGamal dec time: {elgamal_dec_time} ms")
              
              m, aes_dec_time = aes_dec(paeks.paekstobyte(key)[:32], emails[s][e]['ciphertext'])
              received_mails[e] = m
              print(f"AES dec time: {aes_dec_time} ms")
              received_mails[e]["username"] = [users[i]['username'] for i in users if users[i]['email'] == received_mails[e]["from"]][0]
  
  return {"status":"success","data":received_mails}

@app.route('/profile', methods=['GET', 'POST'])
def profile():
  uid = request.get_json()
  u = db.reference('users/').child(uid).get()
  return {"status":"success","username":u["username"],"email":u["email"]}

@app.route('/change_pwd', methods=['GET', 'POST'])
def change_pwd():
  data = request.get_json()
  u = db.reference('users/').child(data[0]['uid']).get()
  if(verify_pwd(u["hash"],u["salt"],data[0]['old'])):
    salt, pwd_hash = hashing_pwd(data[0]['new'])
    db.reference('users/').child(data[0]['uid']).update({'salt': salt, 'hash': pwd_hash})
    return {"status": "success"}
  else: return {"status": "fail", "msg": "Old password is incorrect"}

def perf_paeks(pairing_type, lamda, action):
  print(f"\n{pairing_type} {lamda} PAEKS running...")
  global paeks
  if action == "paeks":
    group = PairingGroup(lamda)
    
    cnt = 10
    avg_time = [0,0,0,0,0,0]
    
    for c in range(cnt):
      start_time = time.time()
      paeks = PAEKS(pairing_type, group)
      end_time = time.time()
      setup_time = (end_time - start_time) * 1000
      
      result, keygens_time = paeks.keygens()
      
      if(pairing_type == 'type1'): 
        pks_size = calc_size(str(paeks.pk_s), 'g')
      elif(pairing_type == 'type3'): 
        pks_size = calc_size(str(paeks.pk_s1), 'g') + calc_size(str(paeks.pk_s2), 'g')
      
      result, keygenr_time = paeks.keygenr()
      pkr_size = calc_size(str(paeks.pk_r), 'g')
      sk_size = len(bin(int(str(paeks.sk_r))))-2
      
      keyword = "meeting"
      
      Cw, paeks_time = paeks.encrypt(keyword)
      
      if(pairing_type == 'type3'):
        Cw['A'] = adjust_hash_size(Cw['A'], 254)
      elif(pairing_type == 'type1'): 
        Cw['A'] = adjust_hash_size(Cw['A'], 1024)
      cw_size = calc_size(Cw['B'], 'g') + len(Cw['A'])
      
      skeyword = "meeting"
      
      Tw, trapdoor_time = paeks.trapdoor(skeyword)
      tw_size = calc_size(Tw, 'g')
      
      result, test_time = paeks.test(Cw, Tw)
      
      avg_time[0] += setup_time
      avg_time[1] += keygens_time
      avg_time[2] += keygenr_time
      avg_time[3] += paeks_time
      avg_time[4] += trapdoor_time
      avg_time[5] += test_time
      
    for i in range(6):
      avg_time[i] = avg_time[i] / cnt
    
    return avg_time
    
  elif action == "hybrid time":
    eg_pk = {}
  
    if(pairing_type == 'type1'):    
      eg_pk['g'] = paeks.g
    elif(pairing_type == 'type3'):    
      eg_pk['g'] = paeks.g1
      
    #fixed alice sender, bob receiver  
    users = db.reference('users/').get()
    paeks.sk_r = paeks.strtopaeks(users["18b7f8d3-7d2a-4808-ba34-ac87fb9ffb3f"]["sk_r"])
    paeks.pk_r = paeks.strtopaeks(users["18b7f8d3-7d2a-4808-ba34-ac87fb9ffb3f"]["pk_r"])
    eg_pk['y'] = paeks.pk_r
    
    all_algo = [[],[],[],[]]
    cnt = 200 #calculate avg of how many times
    comm_cost = [[],[]] #email size, cm size
    
    for s in range(1,6): #msg in 100-500
      avg_time = [0,0,0,0]
      for c in range(cnt): #run for 200 times to calc avg
        eid = str(uuid.uuid4())
        data = [{"from":"alice@paeks.mai.com","to":"bob@paeks.mai.com","subject":"fyp meet urgent","content":"Bob, \nLet's meet on tomorrow at 10am in learning point to discuss about the FYP, because the deadline is around the corner\n"*s*100,"date":"2024-01-01 13:00:00"}]
        m_size = calc_size(data, 'm')/8/1000
        aes_key = paeks.group.random(G1)
        Cm, aes_enc_time = aes_enc(paeks.paekstobyte(aes_key)[:32], eid, data)
        cm_size = calc_size(Cm, 'Cm')/8/1000
        
        if c == 0:
          comm_cost[0].append(m_size)
          comm_cost[1].append(cm_size)
  
        Ck, elgamal_enc_time = elgamal_enc(paeks.group, aes_key, eg_pk)
        ck_size = calc_size(Ck['c1'], 'g') + calc_size(Ck['c2'], 'g')
        eg_pk_size = calc_size(eg_pk['g'], 'g') + calc_size(eg_pk['y'], 'g')
  
        key, elgamal_dec_time = elgamal_dec(paeks.group, Ck, paeks.sk_r)
        
        m, aes_dec_time = aes_dec(paeks.paekstobyte(key)[:32], Cm)
        avg_time[0] += aes_enc_time
        avg_time[1] += aes_dec_time
        avg_time[2] += elgamal_enc_time
        avg_time[3] += elgamal_dec_time
      for i in range(4):
        avg_time[i] = avg_time[i] / cnt
    
      all_algo[0].append(avg_time[0])
      all_algo[1].append(avg_time[1])
      all_algo[2].append(avg_time[2])
      all_algo[3].append(avg_time[3])
    return all_algo, comm_cost

def graph(data, perf):
  plt.figure(num="PAEKS Performance Analysis")
  
  if(perf == "paeks time"):
    x = ["Setup","KeyGenS","KeyGenR","PAEKS","Trapdoor","Test"]
    xaxis = np.arange(len(x))
    plt.bar(xaxis - 0.2, data[0], 0.4, label = 'Type 1')
    plt.bar(xaxis + 0.2, data[1], 0.4, label = 'Type 3')
    plt.xticks(xaxis, x)
    plt.ylabel("Time Taken (ms)")
    plt.title("PAEKS Algorithms Execution Time")
    plt.legend()  
    for i in range(len(x)):
      plt.text(i-0.4,data[0][i], f"{data[0][i]:.1f}")
      plt.text(i,data[1][i], f"{data[1][i]:.1f}")          
    plt.show()
    
  if(perf == "paeks cost"):
    x = ["Private Key","Public Key S","Public Key R","Ciphertext","Trapdoor"]
    xaxis = np.arange(len(x))
    plt.bar(xaxis - 0.2, data[0], 0.4, label = 'Type 1')
    plt.bar(xaxis + 0.2, data[1], 0.4, label = 'Type 3')
    plt.xticks(xaxis, x)
    plt.ylabel("Size (bits)")
    plt.title("PAEKS Communication Cost")
    plt.legend()    
    for i in range(len(x)):
      plt.text(i-0.4,data[0][i], f"{data[0][i]}")
      plt.text(i,data[1][i], f"{data[1][i]}")      
    plt.show()
    
  if(perf == "hybrid time"):
    x = data[1][0]
    labels = ["AES-GCM Encrypt", "AES-GCM Decrypt", "ElGamal Encrypt", "ElGamal Decrypt"]
    y_data = data[0]
    for y, label in zip(y_data, labels):
      plt.plot(x, y, marker='o', label=label)
      for i, j in zip(x, y):
        plt.annotate(f"{j:.2f}", xy=(i, j), xytext=(0, 5), textcoords='offset points')
    plt.xlabel("Size of Email (KB)")
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.6))
    plt.grid(True)
    plt.ylabel("Time Taken (ms)")
    plt.title("AES-GCM and ElGamal Algorithms Execution Time")
    plt.show()
    
  if(perf == "aes cost"):
    x = data[0]
    xaxis = np.arange(len(x))
    plt.bar(xaxis, data[1])
    plt.xticks(xaxis, x)
    plt.xlabel("Email Size (KB)")
    plt.ylabel("Ciphertext Size (KB)")
    plt.title("AES-GCM Ciphertext Communication Cost")
    for i in range(len(x)):
      plt.text(i-0.2,data[1][i], f"{data[1][i]}")
    plt.show()
    
  if(perf == "hybrid cost"):
    x = ["AES-GCM Key","ElGamal Private Key","ElGamal Public Key","ElGamal Ciphertext"]
    xaxis = np.arange(len(x))
    plt.bar(xaxis, data)
    plt.xticks(xaxis, x)
    plt.ylabel("Size (bits)")
    plt.title("AES-GCM and ElGamal Communication Cost")
    for i in range(len(x)):
      plt.text(i-0.1,data[i], f"{data[i]}")
    plt.show()

#Initialise global parameters
group = PairingGroup('BN254')
paeks = PAEKS('type3', group)
params = db.reference('params/').get()

if params is None:
  db.reference('params/').set({'g1': paeks.paekstobyte(paeks.g1), 'g2': paeks.paekstobyte(paeks.g2), 'u': paeks.paekstobyte(paeks.u)})
else:
  paeks.g1 = paeks.strtopaeks(params['g1'])
  paeks.g2 = paeks.strtopaeks(params['g2'])
  paeks.u = paeks.strtopaeks(params['u'])

if __name__ == "__main__":
  #Performance benchmarking
  #type1 = perf_paeks('type1','SS1024', 'paeks')
  #type3 = perf_paeks('type3','BN254', 'paeks')
  #graph([type1, type3], "paeks time")
  #graph([[1024, 2066, 2066, 3090, 2066], [254, 1524, 508, 762, 1016]], "paeks cost")
  
  #hybrid_data = perf_paeks('type3','BN254', 'hybrid time')
  #graph(hybrid_data, 'hybrid time')
  #graph(hybrid_data[1], "aes cost")
  #graph([256, 254, 1016, 1016], "hybrid cost")
  
  #Website hosting
  app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)

