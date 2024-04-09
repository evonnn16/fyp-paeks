from flask import Flask, render_template, request, jsonify
import os
import json
import firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import hashlib

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

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
  "databaseURL": "https://fyp-paeks-default-rtdb.asia-southeast1.firebasedatabase.app/"
})

app = Flask(__name__)

@app.route("/") 
def index():
  return render_template('index.html')

@app.route('/create', methods=['GET', 'POST'])
def insert():
  data = request.get_json()

  emails = db.reference('emails/')
  mail_list = emails.get()
  # print(mail_list)
  id = '-1'
  if(mail_list == None):
    id = 'e0'
  else:
    id = 'e'+str(int(list(mail_list.keys())[-1][1:])+1)
    # get last item, slice e, convert int, +1, convert str+e

  mail = emails.child(id)
  mail.set({
    'from': data[0]['from'],
    'to': data[0]['to'],
    'subject': data[0]['subject'],
    'keyword': data[0]['keyword'],
    'content': data[0]['content'],
    'date': data[0]['date']
  })
  return "Data Inserted"

@app.route('/search', methods=['GET', 'POST'])
def search():
  emails = db.reference('emails/')
  mail_list = emails.get()
  return jsonify(mail_list)

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

@app.route('/login', methods=['GET', 'POST'])
def login():
  data = request.get_json()

  users = db.reference('users/')
  user_list = users.get()

  found = 0
  for u in user_list:
    # print(u,":",user_list[u]["email"])
    if(data[0]['email'] == user_list[u]["email"] and data[0]['pwd'] == user_list[u]["pwd"]):
      # print("match")
      found = 1
      break

  if(found == 1): return "success"
  else: return "fail"

@app.route('/register', methods=['GET', 'POST'])
def register():
  data = request.get_json()

  users = db.reference('users/')
  user_list = users.get()

  id = '-1'
  if(user_list == None):
    id = 'u0'
  else:
    id = 'u'+str(int(list(user_list.keys())[-1][1:])+1)

  same_email = "0"
  if(user_list != None):
    for u in user_list:
      if(data[0]['email'] == user_list[u]["email"]):
        same_email = "1"
        break

  if(same_email == "0"):
    #setup global params if not yet in db, if existed proceed to keygen for both sender & receiver
    params = db.reference('params/').get() 
    if(params == None):
      params = setup() 
      db.reference('params/').set({'g1':params['g1'],'g2':params['g2'],'u':params['u']})
      params = db.reference('params/').get()
    
    #print("params:",params)
    [sk_s,pk_s1,pk_s2] = keygens(params)
    [sk_r,pk_r] = keygenr(params)
      
    user = users.child(id)
    user.set({
      'username': data[0]['username'],
      'email': data[0]['email'],
      'pwd': data[0]['pwd'],
      'sk_s': sk_s,
      'pk_s1': pk_s1,
      'pk_s2': pk_s2,
      'sk_r': sk_r,
      'pk_r': pk_r
    })
    return "success"
  else:
    return "email existed"

if __name__ == "__main__":
  app.run(host="127.0.0.1", port=int(os.environ.get('PORT', 8080)), debug=True)

# @app.route("/test") 
# app.run(host="127.0.0.1", port=8080, debug=True)
# Running on http://127.0.0.1:8080/test http://localhost:8080/test

# @app.route("/") 
# app.run()
# Running on http://localhost:5000/ http://localhost:8080/
