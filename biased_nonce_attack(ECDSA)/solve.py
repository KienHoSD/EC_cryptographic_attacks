from sage.all_cmdline import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long
from ecdsa.ecdsa import curve_256, generator_256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwn import *
import json
p = remote("127.0.0.1", 8777)
p.recvuntil(b"Encrypted flag: ")
enc_flag = p.recvline().strip().decode()
print("Encrypted flag: ", enc_flag)
p.recvuntil(b"Public key: ")
public_key = p.recvline().strip().decode()
split_public_key = public_key.replace('(','').replace(')','').split(',')
public_key_x = int(split_public_key[0],10)
public_key_y = int(split_public_key[1],10)
print("Public key: ", public_key)
leak_outs = p.recv().decode().strip()
split_leak_outs = leak_outs.split('\n')
print(leak_outs)
for i in range(len(split_leak_outs)):
  split_leak_outs[i] = eval(split_leak_outs[i])

outs = split_leak_outs


m_array = []
r_array = []
s_array = []

for out in outs:
  m_array.append(bytes_to_long(sha1(out['msg'].encode()).digest()))
  r_array.append(int(out['r'],16))
  s_array.append(int(out['s'],16))


G = generator_256
P = (public_key_x,public_key_y)
q = G.order()
p = curve_256.p()
a = curve_256.a()
b = curve_256.b()
Curve256 = EllipticCurve(GF(p),[a,b]) # redefine curve256 in sage
G = Curve256((G.x(),G.y())) # map G to sage curve
P = Curve256(P) # map P to sage curve
B = 2**160 # bound of nonce
matrice = Matrix(QQ, len(m_array)+2, len(m_array)+2)

for i in range(len(m_array)):
  matrice[i,i] = q
  
for i in range(len(m_array)):
  matrice[-2,i] = r_array[i]*inverse_mod(s_array[i],q) % q
  matrice[-1,i] = -(m_array[i]*inverse_mod(s_array[i],q)) % q 

matrice[-1,-1] =  B
matrice[-2,-2] =  QQ(B)/QQ(q)

LLLmatrice = matrice.LLL()

for row in LLLmatrice:    
  d = ((QQ(-(row[-2])) * q) / B) % q # -row[-2] because of minus a_i
  try:
    pub = G*d
    if P.xy() == pub.xy():
      print("Found private key d =", d)
      break
  except Exception as e:
    pass
      
encrypted_flag = enc_flag
cipher = AES.new(sha1(str(d).encode()).digest()[:16], AES.MODE_ECB)
print("Found flag:", unpad(cipher.decrypt(bytes.fromhex(encrypted_flag)),16).decode())


