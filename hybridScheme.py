import sys, os, json, re, base64, time
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from Crypto.Cipher import AES
from datetime import datetime

def measure_time(func):
  def wrapper(*args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    execution_time = (end_time - start_time) * 1000
    return result, execution_time
  return wrapper

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
