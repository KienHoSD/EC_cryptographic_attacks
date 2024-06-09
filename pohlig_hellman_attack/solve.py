from Crypto.Cipher import AES
from pwn import remote, process
from sage.all_cmdline import *
		
def unpad(data, block_size):
		return data[:-data[-1]]

def decrypt(key, filein, fileout):
	with open(filein, 'rb') as f:
		data = f.read()
	cipher = AES.new(key, AES.MODE_ECB)
	with open(fileout, 'wb') as f:
		f.write(unpad(cipher.decrypt(data),16))
	print(f"Decrypted file {filein} to file {fileout}")

def pohlig_hellman(P, Q, bound=None):
	n = P.order()
	fac = factor(n)
	print(f"factors: {fac}")
	dlogs = []
	primes = []
	total_bit_prime = 0
	for prime, exponent in fac:
		P_0 = (n // (prime ** exponent)) * P 
		Q_0 = (n // (prime ** exponent)) * Q
		log = discrete_log(Q_0, P_0, operation='+', algorithm='rho')
		dlogs.append(log)
		print(f"DL found = {log}  mod({prime**exponent})")
		primes.append(prime**exponent)

		# Calculate total bit length of primes
		total_bit_prime += (prime**exponent).bit_length()
		if bound:
			print(f"total_bit_prime: {total_bit_prime} bound: {bound}")
			if total_bit_prime > bound:
				break

	print("Calculating in CRT...")
	secret = crt(dlogs, primes)
	return secret

if __name__ == "__main__":
	io = remote("localhost", 8003)
	# io = process(["python3", "chall.py"]) # local testing
	# Elliptic curve parameters
	p = int(io.recvline().strip().split(b" = ")[1])
	a = int(io.recvline().strip().split(b" = ")[1])
	b = int(io.recvline().strip().split(b" = ")[1])
	G = eval(io.recvline().strip().split(b" = ")[1])
	P = eval(io.recvline().strip().split(b" = ")[1])
	E = EllipticCurve(GF(p), [a, b])
	G = E(G)
	P = E(P)

	secret = pohlig_hellman(G, P, bound=128)

	decrypt(secret.to_bytes(16, 'big'), "encrypted.enc","decrypted.pdf")
