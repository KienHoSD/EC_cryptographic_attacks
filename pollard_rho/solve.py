from sage.all import *
from Crypto.Util.number import *
from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad
from hashlib import sha1
from pwn import *


r = remote("localhost", 8088)

p = getPrime(31)
r.sendlineafter(b'Enter your prime: ', str(p).encode())
a = int(r.recvlineS().split('=')[1].strip())
b = int(r.recvlineS().split('=')[1].strip())
p = int(r.recvlineS().split('=')[1].strip())
P = eval(r.recvlineS().split('=')[1].strip())
Q = eval(r.recvlineS().split('=')[1].strip())
r.recvline()

print(f'{a = }')
print(f'{b = }')
print(f'{p = }')
print('P =', P)
print('Q =', Q)


F = GF(p)
E = EllipticCurve(F, [a,b])
P = E(*P)
Q = E(*Q)
n = E.order()

def compute_next(P,Q,Ri,ai,bi):
  y = Ri.xy()[1]
  if 0 <= y <= n//3:
    return Q+Ri, ai, (bi+1) % n
  elif n//3 <= y <= 2*n//3:
    return 2*Ri, 2*ai % n, 2*bi % n
  else:
    return P+Ri, ai+1 % n, bi

def pollard_rho(P,Q,a,b):
  common_list = {}
  R = a*P + b*Q
  while R not in common_list:
    common_list[R]=(a,b)
    R, a, b = compute_next(P,Q,R,a,b)
  c,d = common_list[R]
  print(a,b,c,d)  
  assert b != d, "b cant be d!"
  return (a-c) * pow(d-b,-1,n) % n

def decrypt(key, mess):
  key = sha1(str(key).encode()).digest()[:16]
  iv = mess[:16]
  ciphertext = mess[16:]
  cipher = AES.new(key, AES.MODE_CBC, iv)
  pt = unpad(cipher.decrypt(ciphertext),AES.block_size)
  return pt

d = pollard_rho(P,Q,a,b)
assert P*d == Q, "Can not find secret :(" # check if d (secret) is correct
print("found secret!")
print("secret =",d)

with open('cipher.enc','rb') as f:
  ciphertext = f.read()
  pt = decrypt(d,ciphertext)
  with open('decrypted.pdf','wb') as mess:
    mess.write(pt)
  
