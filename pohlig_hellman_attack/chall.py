from sage.all_cmdline import *
from Crypto.Cipher import AES

def pad(data, block_size):
	return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(key, filein, fileout):
	with open(filein, 'rb') as f:
		data = f.read()
	cipher = AES.new(key, AES.MODE_ECB)
	with open(fileout, 'wb') as f:
		f.write(cipher.encrypt(pad(data, 16)))
	print(f"Encrypted file {filein} to file {fileout}")
	

if __name__ == "__main__":
	# Elliptic curve parameters
	p = 115792089210356248762697446949407573530086143415290314195533631308867097853951  
	a = 115792089210356248762697446949407573530086143415290314195533631308867097853948  
	b = 1235004111951061474045987936620314048836031279781573542995567934901240450608
	E = EllipticCurve(GF(p), [a, b])

	G = E.gens()[0]
	# Generate a random secret key (16 bytes)
	secret = randint(1, 2**(128) - 1)
	P = secret * G

	print(f"{p = }")
	print(f"{a = }")
	print(f"{b = }")
	print("G =", G.xy())
	print("P =", P.xy())
	encrypt(secret.to_bytes(16, 'big'), "Sommerseth+Hoeiland.pdf","encrypted.enc")