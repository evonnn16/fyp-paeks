from flask import Flask, render_template, request, jsonify
import sys, os, json, re, uuid, firebase_admin, hashlib, base64, secrets, time, argparse
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import matplotlib.pyplot as plt
import numpy as np 
from datetime import datetime
from PAEKS import PAEKS
from hybridScheme import aes_enc, aes_dec, elgamal_enc, elgamal_dec

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
  "databaseURL": "https://fyp-paeks-default-rtdb.asia-southeast1.firebasedatabase.app/"
})

app = Flask(__name__)

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
    cw_size = calc_size(cw['B'], 'g') + len(bin(int(str(cw['A']))))-2
    cw['A'] = paeks.paekstobyte(cw['A'])
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
            if isinstance(k['B'], str): 
              k['A'] = paeks.strtopaeks(k['A'])
              k['B'] = paeks.strtopaeks(k['B'])
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
  app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)
