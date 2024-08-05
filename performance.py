import sys, os, json, re, uuid, time, base64
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import matplotlib.pyplot as plt
import numpy as np 
from datetime import datetime
from PAEKS import PAEKS
from hybridScheme import aes_enc, aes_dec, elgamal_enc, elgamal_dec

def perf_paeks(pairing_type, lamda, action):
  print(f"\n{pairing_type} {lamda} PAEKS running...")
  
  # PAEKS
  group = PairingGroup(lamda)
  
  cnt = 200
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
    
    cw_size = calc_size(Cw['B'], 'g') + len(bin(int(str(Cw['A']))))-2
    
    Tw, trapdoor_time = paeks.trapdoor(keyword)
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
  
  # Hybrid ElGamal+AES-GCM
  eg_pk = {}
  
  if(pairing_type == 'type1'):    
    eg_pk['g'] = paeks.g
  elif(pairing_type == 'type3'):    
    eg_pk['g'] = paeks.g1
  eg_pk['y'] = paeks.pk_r
  
  all_algo = [[],[],[],[]]
  comm_cost = [[],[]]
  
  for s in range(1,6): 
    hybrid_avg_time = [0,0,0,0]
    for c in range(cnt): 
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
      hybrid_avg_time[0] += aes_enc_time
      hybrid_avg_time[1] += aes_dec_time
      hybrid_avg_time[2] += elgamal_enc_time
      hybrid_avg_time[3] += elgamal_dec_time
      
    for i in range(4):
      hybrid_avg_time[i] = hybrid_avg_time[i] / cnt
  
    all_algo[0].append(hybrid_avg_time[0])
    all_algo[1].append(hybrid_avg_time[1])
    all_algo[2].append(hybrid_avg_time[2])
    all_algo[3].append(hybrid_avg_time[3])
  
  return avg_time, all_algo, comm_cost

def calc_size(data, data_type):
  if data_type == 'Cm':
    return len(base64.b64decode(data['nonce']))*8 + len(base64.b64decode(data['header']))*8 + len(base64.b64decode(data['tag']))*8 + len(base64.b64decode(data['ciphertext']))*8
  elif data_type == 'g':    
    bsize = [int(i) for i in re.findall(r'\d+', str(data))]
    return sum(len(bin(i))-2 for i in bsize)
  elif data_type == 'm':
    return len(json.dumps(data).encode('utf-8'))*8
    
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

if __name__ == "__main__":
  type1 = perf_paeks('type1','SS1024', 'paeks')
  type3 = perf_paeks('type3','BN254', 'paeks')
  graph([type1[0], type3[0]], "paeks time")
  graph([[1024, 2066, 2066, 3090, 2066], [254, 1524, 508, 762, 1016]], "paeks cost")
  graph([type3[1], type3[2]], 'hybrid time')  
  graph(type3[2], "aes cost")
  graph([256, 254, 1016, 1016], "hybrid cost")
