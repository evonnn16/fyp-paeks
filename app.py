from flask import Flask, render_template, request, jsonify
import os
import json
import firebase_admin
from firebase_admin import credentials, db
# from charm.toolbox.ecgroup import ECGroup, ZR, G
# from Crypto.PublicKey import ECC

# mykey = ECC.generate(curve='p256')

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
    user = users.child(id)
    user.set({
      'username': data[0]['username'],
      'email': data[0]['email'],
      'pwd': data[0]['pwd']
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
