from sage.all import *
from Crypto.Cipher import AES 
from pwn import remote, process

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
  assert b != d, "b cant be d!"
  return int((a-c) * pow(d-b,-1,n) % n) # convert Integer (sage) to int (python)

def unpad(data, block_size):
		return data[:-data[-1]]

def decrypt(key, filein, fileout):
		with open(filein, 'rb') as f:
				data = f.read()
		cipher = AES.new(key, AES.MODE_ECB)
		with open(fileout, 'wb') as f:
				f.write(unpad(cipher.decrypt(data),16))
		print(f"Decrypted file {filein} to file {fileout}")

if __name__ == "__main__":
  io = remote("localhost", 8002)
  # io = process(["python3", "chall.py"]) # local testing
  print(io.recvuntil(b"Please wait a moment, we are generating parameters for Elliptic Curve...\n").decode())
  a = int(io.recvlineS().split('=')[1].strip())
  b = int(io.recvlineS().split('=')[1].strip())
  p = int(io.recvlineS().split('=')[1].strip())
  P = eval(io.recvlineS().split('=')[1].strip())
  Q = eval(io.recvlineS().split('=')[1].strip())
  io.recvline()

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
  d = pollard_rho(P,Q,a,b)
  assert P*d == Q, "Wrong secret :<" # check if d (secret) is correct
  print("found secret!")
  print("secret =",d)

  decrypt(int.to_bytes(d, 16), "encrypted.enc", "decrypted.pdf")
