from flask import Flask, render_template, request, jsonify
import sys, os, json, re, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import hashlib, base64, secrets, time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from Crypto.Util.number import getPrime, getRandomRange
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
    A = self.hash2(repr((self.u ** self.sk_s) ** r).encode()).hexdigest()
    v = self.group.hash((w, self.pk_r ** self.sk_s),ZR) #H1
  
    if(self.pairing_type == 'type3'):
      B = self.g1**(v*r) * self.pk_r**r
    elif(self.pairing_type == 'type1'):
      B = self.g**(v*r) * self.pk_r**r
    return {'A':A, 'B':B}
  
  @measure_time
  def trapdoor(self, w2):
    if(self.pairing_type == 'type3'):
      v2 = self.group.hash((w2, self.pk_s1 ** self.sk_r),ZR) #H1
      Tw = self.pk_s2**(1/(self.sk_r + v2))
    elif(self.pairing_type == 'type1'):
      v2 = self.group.hash((w2, self.pk_s ** self.sk_r),ZR) #H1
      Tw = self.pk_s**(1/(self.sk_r + v2))
    return Tw
  
  @measure_time
  def test(self, Cw, Tw):
    pairing = pair(Tw, Cw['B'])
    lhs = self.hash2(repr(pairing).encode()).hexdigest()
    return lhs == Cw['A']
  
  def paekstobyte(self, paeks_obj):
    return self.group.serialize(paeks_obj)
  
  def bytetopaeks(self, byte_obj):
    return self.group.deserialize(byte_obj)
  
  def strtobyte(self, string_obj):
    #return bytes(string_obj, 'utf-8')
    return string_obj.encode('utf-8')
  
  def bytetostr(self, byte_obj):
    return string_obj.decode('utf-8')
  
  def strtopaeks(self, string_obj):
    return self.group.deserialize(bytes(string_obj, 'utf-8'))
    #return self.group.deserialize(string_obj.encode('utf-8'))

'''
def setup(pairing_type, group):

  if(pairing_type == 'type3'):
    g1 = group.random(G1)
    g2 = group.random(G2)
    u = pair(g1, g2)
    params = {'g1':group.serialize(g1),'g2':group.serialize(g2),'u':group.serialize(u)}
  elif(pairing_type == 'type1'):
    g = group.random(G1)
    u = pair(g, g)
    params = {'g':group.serialize(g),'u':group.serialize(u)}
  return params

def keygens(pairing_type, group, params):
  y = group.random(ZR)
  sk_s = group.serialize(y) #convert object to byte
  
  if(pairing_type == 'type3'):
    #print(f"g1 byte:{params['g1']}\ng1 str:{params['g1'].decode('utf-8')}\ng1 pairing element:{group.deserialize(params['g1'])}\ng1 convert:{group.deserialize(bytes(params['g1'].decode('utf-8'), 'utf-8'))}")
    pk_s1 = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** y) #in db store as str, convert to byte then deserialize
    pk_s2 = group.serialize(group.deserialize(bytes(params['g2'], 'utf-8')) ** y)
    return [sk_s,pk_s1,pk_s2]
  elif(pairing_type == 'type1'):
    pk_s = group.serialize(group.deserialize(bytes(params['g'], 'utf-8')) ** y)
    return [sk_s,pk_s]

def keygenr(pairing_type, group, params):
  x = group.random(ZR)
  sk_r = group.serialize(x)
  
  if(pairing_type == 'type3'):
    pk_r = group.serialize(group.deserialize(bytes(params['g1'], 'utf-8')) ** x)
  elif(pairing_type == 'type1'):
    pk_r = group.serialize(group.deserialize(bytes(params['g'], 'utf-8')) ** x)
  return [sk_r,pk_r]

def paeks(pairing_type, group, params, w, sk_s, pk_r):
  r = group.random(ZR)
  temp = (group.deserialize(bytes(params['u'], 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8')))**r
  A = hash2(repr(temp).encode()).hexdigest()
  temp = group.deserialize(bytes(pk_r, 'utf-8'))**group.deserialize(bytes(sk_s, 'utf-8'))
  v = group.hash((w,temp),ZR) #H1
  
  if(pairing_type == 'type3'):
    B = group.deserialize(bytes(params['g1'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
  elif(pairing_type == 'type1'):
    B = group.deserialize(bytes(params['g'], 'utf-8'))**(v*r) * group.deserialize(bytes(pk_r, 'utf-8'))**r
  return {'A':str(A), 'B':group.serialize(B)}

def trapdoor(pairing_type, group, params, w2, pk_s1, pk_s2, sk_r):
  sk_r = group.deserialize(bytes(sk_r, 'utf-8'))
  #temp2 = group.deserialize(bytes(pk_s1, 'utf-8'))**sk_r
  v2 = group.hash((w2,group.deserialize(bytes(pk_s1, 'utf-8'))**sk_r),ZR) #H1
  if(pairing_type == 'type3'):
    Tw = group.deserialize(bytes(pk_s2, 'utf-8'))**(1/(sk_r+v2))
  elif(pairing_type == 'type1'):
    Tw = group.deserialize(bytes(pk_s1, 'utf-8'))**(1/(sk_r+v2))
  return group.serialize(Tw)

def test(pairing_type, group, Cw, Tw):
  try:
    #if(pairing_type == 'type3'):
    pairing = pair(group.deserialize(Tw),group.deserialize(bytes(Cw['B'], 'utf-8')))
    #elif(pairing_type == 'type1'):
    #  pairing = pair(group.deserialize(Tw),group.deserialize(Cw['B']))
    lhs = hash2(repr(pairing).encode()).hexdigest()
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
'''
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
'''
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

def tee(group, msg, pk):
  pk = {
      'g': group.deserialize(pk['g']),
      'y': group.deserialize(pk['y'])
  }
  #print(f"tee pk: {pk}")
  
  #m = int.from_bytes(msg, 'big')
  #m = pk['g'] ** msg # Map scalar to a point
  k = group.random(ZR)
  #print(f"k: {k}")
  c1 = pk['g'] ** k
  #print(f"c1: {c1}")
  c2 = msg * (pk['y'] ** k)
  #print(f"c2: {c2}")
  return {'c1': c1, 'c2': c2}

def ted(group, Ck, sk, pk):
  pk = {
      'g': group.deserialize(pk['g']),
      'y': group.deserialize(pk['y'])
  }
  x = group.deserialize(sk)
  
  c1, c2 = Ck['c1'], Ck['c2']
  #print(f"dec c1: {c1}")
  #print(f"dec c2: {c2}")
  #m = c2 * ((c1 ** x) ** -1)
  m = c2 / (c1 ** x)
  return m
'''
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
  #print(f"sk_s: {paeks.sk_s}\npk_s1: {paeks.pk_s1}\npk_s2: {paeks.pk_s2}\nsk_r: {paeks.sk_r}\npk_r: {paeks.pk_r}")
  print(f"keygens time: {keygens_time}\nkeygenr time: {keygenr_time}")
  
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
  #print(f"s: {users[s]['username']}, sk_s: {paeks.sk_s}")
  
  for u in users:      
    if(data[0]['to'] == users[u]["email"]):
      paeks.pk_r = paeks.strtopaeks(users[u]["pk_r"])
      r = u
      break
  else: return {"status":"fail","msg":"Receiver's email address not found"}
  #print(data[0]['to'],"pk_r:",paeks.pk_r)
  
  keyword = data[0]['keyword'].split(' ')
  keyword.sort()
  #print(keyword)
  
  Cw, paeks_time = paeks.encrypt(str(keyword))
  print("Cw:",Cw)
  bsize = [int(i) for i in str(Cw['B'])[1:-1].split(", ")]
  print(f"Cw size: {sum(len(bin(i))-2 for i in bsize)+len(Cw['A'])*4} bits")
  Cw['B'] = paeks.paekstobyte(Cw['B'])
  print("paeks time taken:",paeks_time)
  
  eid = str(uuid.uuid4())
  
  aes_key = group.random(G1)
  Cm, aes_enc_time = aes_enc(paeks.paekstobyte(aes_key)[:32], eid, data)
  #print(f"aes key: {aes_key}")
  #print(f"aes encrypt: {Cm}")
  print(f"\naes enc time: {aes_enc_time}")
  
  eg_pk = {'g': paeks.g1, 'y': paeks.pk_r}
  Ck, elgamal_enc_time = elgamal_enc(paeks.group, aes_key, eg_pk)
  Ck['c1'] = paeks.paekstobyte(Ck['c1'])
  Ck['c2'] = paeks.paekstobyte(Ck['c2'])
  #print(f"Ck: {Ck}")
  print(f"\nelgamal enc time: {elgamal_enc_time}")
  
  db.reference('emails/').child(r).child(s).child(eid).set({
    'key': Ck,
    'ciphertext': Cm,
    'keyword': Cw
  })
  '''
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
  '''
  return {"status": "success", "msg":"Email is sent successfully!"}

@app.route('/search', methods=['GET', 'POST'])
def search():
  data = request.get_json()
  
  global paeks
  
  users = db.reference('users/').get()
  r = data[0]['uid']
  paeks.sk_r = paeks.strtopaeks(users[r]["sk_r"])
  #print(f"{users[r]['username']} sk_r: {paeks.sk_r}")
  
  keyword = data[0]['keyword'].split(' ')
  keyword.sort()
  #print(keyword)
  
  emails = db.reference('emails/').child(r).get()
  received_mails = {}
  if(emails != None):
    for s in emails:
      paeks.pk_s1 = paeks.strtopaeks(users[s]["pk_s1"])
      paeks.pk_s2 = paeks.strtopaeks(users[s]["pk_s2"])
      #print(f"{users[s]['username']}: pk_s1: {paeks.pk_s1}, pk_s2: {paeks.pk_s2}")
      
      Tw, trapdoor_time = paeks.trapdoor(str(keyword))
      print(f"trapdoor: {Tw}")
      print("trapdoor time taken:",trapdoor_time)
      bsize = [int(i) for i in re.findall(r'\d+', str(Tw))]
      print(f"Tw size: {sum(len(bin(i))-2 for i in bsize)} bits")
      #tw_size = sys.getsizeof(Tw)*8
      
      for e in emails[s]:
        emails[s][e]["keyword"]['B'] = paeks.strtopaeks(emails[s][e]["keyword"]['B'])
        result, test_time = paeks.test(emails[s][e]["keyword"],Tw)
        print("test time taken:",test_time)
        
        if(result):
          emails[s][e]['key']['c1'] = paeks.strtopaeks(emails[s][e]['key']['c1'])
          emails[s][e]['key']['c2'] = paeks.strtopaeks(emails[s][e]['key']['c2'])
          key, elgamal_dec_time = elgamal_dec(paeks.group, emails[s][e]['key'], paeks.sk_r)
          #print(f"dec aes key: {key}")
          print(f"elgamal dec time: {elgamal_dec_time}")
          
          m, aes_dec_time = aes_dec(paeks.paekstobyte(key)[:32], emails[s][e]['ciphertext'])
          received_mails[e] = m
          print("aes dec time:",aes_dec_time)
          received_mails[e]["username"] = [users[k]['username'] for k in users if users[k]['email'] == received_mails[e]["from"]][0]
        '''
        perf = db.reference('performance/time/test/')
        if(perf.get() == None): perf.set({"sum":test_time,"count":1})
        else: perf.set({"sum":perf.get()["sum"] + test_time,"count":perf.get()["count"]+1})
      
      perf = db.reference('performance/time/trapdoor/')
      if(perf.get() == None): perf.set({"sum":trapdoor_time,"count":1})
      else: perf.set({"sum":perf.get()["sum"] + trapdoor_time,"count":perf.get()["count"]+1})
      
      perf = db.reference('performance/size/trapdoor/')
      if(perf.get() == None): perf.set({"sum":tw_size,"count":1})
      else: perf.set({"sum":perf.get()["sum"] + tw_size,"count":perf.get()["count"]+1})'''
  
  #print(f"search result:{received_mails}")
  
  return {"status":"success","data":received_mails}

@app.route('/profile', methods=['GET', 'POST'])
def profile():
  uid = request.get_json()
  u = db.reference('users/').child(uid).get()
  return {"status":"success","username":u["username"],"email":u["email"]}

def perf_paeks(pairing_type, lamda):
  print(f"\n{pairing_type} {lamda} PAEKS running...")
  
  group = PairingGroup(lamda)
  
  eg_pk = {}
    
  #print("\nSetup...")
  start_time = time.time()
  paeks = PAEKS(pairing_type, group)
  end_time = time.time()
  setup_time = (end_time - start_time) * 1000
  #print(f"params u: {paeks.u}")
  
  if(pairing_type == 'type1'):    
    eg_pk['g'] = paeks.paekstobyte(paeks.g)
    #params['g'] = params['g'].decode('utf-8')
    #print(f"params g: {paeks.g}")
  elif(pairing_type == 'type3'):    
    eg_pk['g'] = paeks.paekstobyte(paeks.g1)
    #params['g1'] = params['g1'].decode('utf-8')
    #params['g2'] = params['g2'].decode('utf-8')
    #print(f"params g1: {paeks.g1}")
    #print(f"params g2: {paeks.g2}")
  #params['u'] = params['u'].decode('utf-8')  
  
  #print("\nKeyGen...")
  result, keygens_time = paeks.keygens()
  '''start_time = time.time()
  paeks.keygens()
  end_time = time.time()
  keygens_time = (end_time - start_time) * 1000'''
  
  if(pairing_type == 'type1'):
    '''start_time = time.time()
    [sk_s,pk_s] = keygens(pairing_type, group, params)
    end_time = time.time()'''    
    #print(f"sk_s: {paeks.sk_s}\npk_s: {paeks.pk_s}")
  elif(pairing_type == 'type3'):
    '''start_time = time.time()
    [sk_s,pk_s1,pk_s2] = keygens(pairing_type, group, params)
    end_time = time.time()'''    
    #print(f"sk_s: {paeks.sk_s}\npk_s1: {paeks.pk_s1}\npk_s2: {paeks.pk_s2}")
  
  result, keygenr_time = paeks.keygenr()
  '''start_time = time.time()
  paeks.keygenr()
  #[sk_r,pk_r] = keygenr(pairing_type, group, params)
  end_time = time.time()
  keygenr_time = (end_time - start_time) * 1000  '''
  print(f"sk_r: {paeks.sk_r}\npk_r: {paeks.pk_r}")
  
  eg_sk = paeks.paekstobyte(paeks.sk_r)
  eg_pk['y'] = paeks.paekstobyte(paeks.pk_r)
  #print(f"sk_r: {group.deserialize(sk_r)}")
  
  sk_size = len(eg_sk)*8
  pk_size = len(eg_pk)*8
  
  aes_key = group.random(G1)
  #print("aes key:",aes_key)
  #print(f"size of aes key: {len(group.serialize(aes_key))*8}")
  
  Cm = taes_encrypt(paeks.paekstobyte(aes_key)[:32], "eid", "hello there")
  
  Ck = tee(group, aes_key, eg_pk)
  m = ted(group, Ck, eg_sk, eg_pk)
  #print("elgamal decode aes key:",m)
  
  #print("aes decrypt:",taes_decrypt(paeks.paekstobyte(m)[:32], Cm))
  
  keyword = "meetingurgent makan"
  
  #print("\nPAEKS...")
  for n in range(1,6):
    total_paeks = 0
    for i in range(n*100):
      Cw, paeks_time = paeks.encrypt(keyword)
      total_paeks += paeks_time
    print(f"{n*100} keywords: {total_paeks} ms")
  '''start_time = time.time()
  #Cw = paeks(pairing_type, group, params, keyword, sk_s.decode('utf-8'), pk_r.decode('utf-8'))
  A,B = paeks.encrypt(keyword)
  end_time = time.time()
  paeks_time = (end_time - start_time) * 1000'''
  #print(f"Cw: {Cw}")
  #cw_size = len(Cw['B'])*8 + len(Cw['A'])
  cw_size = len(paeks.strtobyte(Cw['A'])) + len(paeks.paekstobyte(Cw['B']))
  
  #if(pairing_type == 'type3'):
  #Cw['B'] = Cw['B'].decode('utf-8')
  
  skeyword = "meetingurgent makan"
  
  #print("\nTrapdoor...")
  Tw, trapdoor_time = paeks.trapdoor(skeyword)
  '''start_time = time.time()
  Tw = paeks.trapdoor(skeyword)
  end_time = time.time()
  trapdoor_time = (end_time - start_time) * 1000'''
  #print(f"Tw: {Tw}")
  tw_size = len(paeks.paekstobyte(Tw))*8
  
  '''
  if(pairing_type == 'type1'):
    start_time = time.time()
    Tw = trapdoor(pairing_type, group, params, skeyword, pk_s.decode('utf-8'), "", sk_r.decode('utf-8'))
    end_time = time.time()
    trapdoor_time = (end_time - start_time) * 1000
  elif(pairing_type == 'type3'):
    start_time = time.time()
    Tw = trapdoor(pairing_type, group, params, skeyword, pk_s1.decode('utf-8'), pk_s2.decode('utf-8'), sk_r.decode('utf-8'))
    end_time = time.time()
    trapdoor_time = (end_time - start_time) * 1000'''
  
  #print("\nTest...")
  result, test_time = paeks.test(Cw, Tw)
  '''start_time = time.time()
  result = paeks.test({'A':A,'B':B}, Tw)
  end_time = time.time()
  test_time = (end_time - start_time) * 1000'''
  #print(f"test result: {result}")
  
  return [[setup_time,keygens_time,keygenr_time,paeks_time,trapdoor_time,test_time],[sk_size,pk_size,cw_size,tw_size]]

def avg_exec_time(pairing_type, curve):
  print(f"\n{pairing_type} {curve} PAEKS running...")
  setup_times = []
  keygens_times = []
  keygenr_times = []
  paeks_times = []
  trapdoor_times = []
  test_times = []
  
  for i in range(100):
    data = perf_paeks(pairing_type, curve)
    
    setup_times.append(data[0][0])
    keygens_times.append(data[0][1])
    keygenr_times.append(data[0][2])
    paeks_times.append(data[0][3])
    trapdoor_times.append(data[0][4])
    test_times.append(data[0][5])
  
  average_setup_time = np.mean(setup_times)
  average_keygens_time = np.mean(keygens_times)
  average_keygenr_time = np.mean(keygenr_times)
  average_paeks_time = np.mean(paeks_times)
  average_trapdoor_time = np.mean(trapdoor_times)
  average_test_time = np.mean(test_times)
  
  return [[average_setup_time, average_keygens_time, average_keygenr_time, average_paeks_time, average_trapdoor_time, average_test_time],[]]

def total_exec_time(pairing_type, curve):
  print(f"\n{pairing_type} {curve} PAEKS running...")
  
  exec_counts = [100, 200, 300, 400, 500]
  total_times = {count: [] for count in exec_counts}
    
  for count in exec_counts:
    setup_times = []
    keygens_times = []
    keygenr_times = []
    paeks_times = []
    trapdoor_times = []
    test_times = []
    
    for i in range(count):
      data = perf_paeks(pairing_type, curve)
      
      setup_times.append(data[0][0])
      keygens_times.append(data[0][1])
      keygenr_times.append(data[0][2])
      paeks_times.append(data[0][3])
      trapdoor_times.append(data[0][4])
      test_times.append(data[0][5])
        
    total_setup_time = np.sum(setup_times)
    total_keygens_time = np.sum(keygens_times)
    total_keygenr_time = np.sum(keygenr_times)
    total_paeks_time = np.sum(paeks_times)
    total_trapdoor_time = np.sum(trapdoor_times)
    total_test_time = np.sum(test_times)
    
    total_times[count] = [
      total_setup_time, 
      total_keygens_time, 
      total_keygenr_time, 
      total_paeks_time, 
      total_trapdoor_time, 
      total_test_time
    ]
    
  return total_times

def graph(data1, data2, perf):  
  plt.figure(num="PAEKS Performance Analysis")
  
  #TODO: decide whether to put performance generation on website or thru code only
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
  
  if(perf == "perf"):
    x = ["Setup","KeyGenS","KeyGenR","PAEKS","Trapdoor","Test"]
    xaxis = np.arange(len(x))
    plt.bar(xaxis - 0.2, data1[0], 0.4, label = 'Type 1')
    plt.bar(xaxis + 0.2, data2[0], 0.4, label = 'Type 3')
    plt.xticks(xaxis, x)
    plt.ylabel("Time (ms)")
    plt.title("Algorithms Execution Time")
    plt.legend()
  
    for i in range(len(x)):
      plt.text(i-0.4,data1[0][i], f"{data1[0][i]:.1f}")
      plt.text(i,data2[0][i], f"{data2[0][i]:.1f}")
          
    plt.show()
  
  '''
  x = ["Private Key","Public Key","Ciphertext","Trapdoor"]
  xaxis = np.arange(len(x))
  plt.bar(xaxis - 0.2, data1[1], 0.4, label = 'Type 1')
  plt.bar(xaxis + 0.2, data2[1], 0.4, label = 'Type 3')
  plt.xticks(xaxis, x)
  plt.ylabel("Size (bits)")
  plt.title("Communication Cost")
  plt.legend()
  
  for i in range(len(x)):
    plt.text(i-0.4,data1[1][i], f"{data1[1][i]}")
    plt.text(i,data2[1][i], f"{data2[1][i]}")
    
  plt.show()
  '''
  
  if(perf == "linear"):
    x = ["100","200","300","400","500"]
    plt.plot(x, data1, marker='o', label = "Type 1")
    plt.plot(x, data2, marker='o', label = "Type 3")
    plt.xlabel("Number of keywords")
    plt.ylabel("Time (ms)")
    plt.title("PAEKS Encryption Algorithm Execution Time")
    plt.legend()
    plt.grid(True)          
    plt.show()


group = PairingGroup('BN254')
paeks = PAEKS('type3', group)
params = db.reference('params/').get()

if params is None:
  db.reference('params/').set({'g1': paeks.paekstobyte(paeks.g1), 'g2': paeks.paekstobyte(paeks.g2), 'u': paeks.paekstobyte(paeks.u)})
  #print(f"new init: {paeks.g1}\n{paeks.g2}\n{paeks.u}")
else:
  paeks.g1 = paeks.strtopaeks(params['g1'])
  paeks.g2 = paeks.strtopaeks(params['g2'])
  paeks.u = paeks.strtopaeks(params['u'])
  #print(f"ady init: {paeks}\n{paeks.g2}\n{paeks.u}")
#print(f"global init:\n g1: {paeks.g1}\ng2: {paeks.g2}\nu: {paeks.u}")

if __name__ == "__main__":
  #type1 = avg_exec_time('type1','SS512')
  #type1 = perf_paeks('type1','SS512')
  #type3 = perf_paeks('type3','SS512')
  #type3 = avg_exec_time('type3','SS512')
  #type1 = perf_paeks('type1','SS1024')
  #type3 = perf_paeks('type3','BN254')
  #graph(type1, type3, "time")
  #graph([6611.426115036011, 13251.993417739868, 19288.49983215332, 26891.41607284546, 32149.068355560303], [1648.468017578125, 2997.518539428711, 6832.550525665283, 7501.449108123779, 10109.870195388794], "linear") #paeks encrypt
  app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)

