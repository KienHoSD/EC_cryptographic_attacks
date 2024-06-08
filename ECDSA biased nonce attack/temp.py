from sage.all_cmdline import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long
from ecdsa.ecdsa import curve_256, generator_256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
outs = [
{'msg': 'I have hidden the secret flag as a point of an elliptic curve using my private key.', 'r': '0x5bc2867b91899b2b8a6f345c498f083be348248c77dd2d661e20a46f4ec6b356', 's': '0x282f6cef5f36b8bc8237b43029210d2a3f485525c5814457d2a6a5994c1098e3'},
{'msg': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', 'r': '0x2d7f3be39906fb3840f5efadb0cd16986fb768394d8a7aa1251e39829aaa458a', 's': '0x6fc4368864bd9cc4cc0ef5f09726a1933ba8b2b665391002962f4606373738'},
{'msg': 'Good luck!', 'r': '0xd58219d04b8cd84e6792d6237a184c6934bae6a17c771cacc6ec239dcc9f4489', 's': '0xa80ba69cb4e1e00ca4b16c84437e6b1219ee0e69768843ffb81fc9a7b746dfd1'}
]
print(outs[0])

m_array = []
r_array = []
s_array = []

for out in outs:
  m_array.append(bytes_to_long(sha1(out['msg'].encode()).digest()))
  r_array.append(int(out['r'],16))
  s_array.append(int(out['s'],16))


G = generator_256
P = (104686943835883737185677309621264820857221617124192612417519017178012344115814, 45021098217299753828514723659906157820769463490498131038292811910323214865891) 
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
      
encrypted_flag = "456b7b6d2291b1913074b40bd855781928875bd209fe1d70007735034753b4c1"
cipher = AES.new(sha1(str(d).encode()).digest()[:16], AES.MODE_ECB)
print(unpad(cipher.decrypt(bytes.fromhex(encrypted_flag)),16).decode())