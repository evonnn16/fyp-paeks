from flask import Flask, render_template, request, jsonify
import sys, os, json, re, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import base64, secrets, time
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
    
class PAEKS:
  def __init__(self, pairing_type, group):
    self.pairing_type = pairing_type
    self.group = group
    
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
    A = self.group.hash(self.group.serialize((self.u ** self.sk_s) ** r), ZR)      
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
    lhs = self.group.hash(self.group.serialize(pairing), ZR)
    return lhs == Cw['A']
  
  def paekstobyte(self, paeks_obj):
    return self.group.serialize(paeks_obj)
  
  def strtopaeks(self, string_obj):
    return self.group.deserialize(bytes(string_obj, 'utf-8'))

if __name__ == "__main__":
  group = PairingGroup("BN254")
  paeks = PAEKS("type3", group)
  print(f"params:\ng1: {paeks.g1}\ng2: {paeks.g2}\nu: {paeks.u}")
   
  paeks.keygens()
  print(f"\nSender private key: {paeks.sk_s}\nSender public key 1: {paeks.pk_s1}\nSender public key 2: {paeks.pk_s2}")
  paeks.keygenr()
  print(f"\nReceiver private key: {paeks.sk_r}\nReceiver public key: {paeks.pk_r}")
  
  keyword = "meeting"
    
  Cw, paeks_time = paeks.encrypt(keyword)
  print(f"\nCiphertext: {Cw}")
  
  Tw, trapdoor_time = paeks.trapdoor(keyword)
  print(f"\nTrapdoor: {Tw}")
  
  result, test_time = paeks.test(Cw, Tw)
  
  if result:
    print("\nTest successful")
  else:
    print("\nTest unsuccessful")
