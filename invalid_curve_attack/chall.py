from Crypto.Util.number import inverse, bytes_to_long
from Crypto.Cipher import AES
from random import randint


def add(P, Q, E):
	if (P == (0, 0)):
		return Q
	elif (Q == (0, 0)):
		return P
	else:
		Ea, Ep = E['a'], E['p']
		x1, y1 = P
		x2, y2 = Q
		if (x1 == x2 and y1 == -y2 % Ep):
			return (0, 0)
		else:
			if P != Q:
				l = (y2 - y1) * inverse(x2 - x1, Ep)
			else:
				l = (3 * (x1**2) + Ea) * inverse(2 * y1, Ep)
		x3 = (l**2 - x1 - x2) % Ep
		y3 = (l * (x1 - x3) - y1) % Ep
		return x3, y3

def multiply(P, n, E):
	Q = P
	R = (0, 0)
	while n > 0:
		if n % 2 == 1:
			R = add(R, Q, E)
		Q = add(Q, Q, E)
		n //= 2
	return R

def pad(data, block_size):
	return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(key, filein, fileout):
	with open(filein, 'rb') as f:
		data = f.read()
	cipher = AES.new(key, AES.MODE_ECB)
	with open(fileout, 'wb') as f:
		f.write(cipher.encrypt(pad(data, 16)))
	print(f"Encrypted file {filein} to file {fileout}")


if __name__ == '__main__':
	
	# Curve25519 parameters
	a = 486662
	b = 1
	p = 2**255 - 19
	E = {'a': a, 'b': b, 'p': p}  # Curve25519

	print("Establishing the TLS handshake...\n")
	secret = randint(1, p-1)
	encrypt(secret.to_bytes(32, 'big')[:16], "2017-554.pdf", "encrypted.enc")

	while True:
		C = input("Awaiting public key of the client (enter x y):\n")
		try:
			x, y = [int(i) for i in C.strip().split()]
			S = multiply((x, y), bytes_to_long(secret.to_bytes(32, 'big')), E)
			print(f"Shared secret: {S}\n")
		except Exception as e:
			print(f"Error occurred: {e}\n")
