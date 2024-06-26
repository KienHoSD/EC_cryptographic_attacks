from sage.all_cmdline import *
from Crypto.Cipher import AES
from pwn import remote, process

def solveDL(E):
	while True:
		try:
			p = E['p']
			a = E['a']
			b = randint(1, p)
			E = EllipticCurve(GF(p), [a, b])
			order = E.order()
			factors = prime_factors(order)

			valid = []
			for factor in factors:
				if factor <= 2**36:
					valid.append(factor)

			prime = valid[-1]

			G = E.gen(0) * int(order // prime)

			# Here we send G to the server
			tmp_point = G.xy()
			tmp_x, tmp_y = str(tmp_point[0]), str(tmp_point[1])
			tmp_point = tmp_x + " " + tmp_y
			break
		except Exception as e:
			print(e)
			print("Error in generating the curve")
			print("Trying again")
			continue

	message = b"Awaiting public key of the client (enter x y):\n"
	io.sendlineafter(message, tmp_point)

	# We get back P which is G * k
	data = io.recvline()
	print(data.decode().strip())

	if b"Error" in data:
		print("An error on the server occured")
		return None, None

	P = eval(data[len("Shared secret: "):])

	try:
		P = E(P)
		dlog = discrete_log(P, G, operation="+", algorithm="bsgs")
		print(f"DL found: {dlog}")
		print(f"Prime: {prime}")
	except Exception as e:
		print(e)
		print("Error in getting the discrete log")
		return None, None

	return dlog, prime

def getDLs(E):
	dlogs = []
	primes = []
	total_primes_bit_size = 0
	while total_primes_bit_size < p.bit_length():
		dlog, prime = solveDL(E)
		if dlog and prime:
			dlogs.append(dlog)
			primes.append(prime)
		else:
			print("Error in getting the discrete log")
			continue
		total_primes_bit_size += prime.bit_length()
		print(f"total primes bit size: {total_primes_bit_size}, need {p.bit_length()}")
	return dlogs, primes

def unpad(data, block_size):
		return data[:-data[-1]]

def decrypt(key, filein, fileout):
		with open(filein, 'rb') as f:
				data = f.read()
		cipher = AES.new(key, AES.MODE_ECB)
		with open(fileout, 'wb') as f:
				f.write(unpad(cipher.decrypt(data),16))
		print(f"Decrypted file {filein} to file {fileout}")

def pwn(E):
	dlogs, primes = getDLs(E)
	print(f"dlogs: {dlogs}")
	print(f"primes: {primes}")
	super_secret = CRT_list(dlogs, primes)
	return int(super_secret) # convert Integer to int


if __name__ == "__main__":
	# Curve25519 parameters (from the server) usually used for key exchange
	a = 486662
	b = 1
	p = 2**255 - 19
	E = {'a': a, 'b': b, 'p': p}

	io = remote("localhost", 8004)
	# io = process(["python3", "chall.py"]) # local testing

	secret = pwn(E)
	print(f"secret:", secret)
	decrypt(secret.to_bytes(32, 'big'), "encrypted.enc", "decrypted.pdf")