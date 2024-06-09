from sage.all import *
from Crypto.Cipher import AES
from pwn import process, remote
import multiprocessing

def compute_baby_steps(start, end, P, queue):
		lookup = {j * P: j for j in range(start, end)}
		queue.put(lookup)

def compute_giant_steps(start, end, m, P, Q, lookup_table, queue):
	for i in range(start, end):
		temp = Q - (i * m) * P
		if temp in lookup_table:
			queue.put((i * m + lookup_table[temp]) % P.order())
			return
	queue.put(None)

def bsgs_ecdlp(P, Q, E, num_processes=8):
	if Q == E((0, 1, 0)):
		return P.order()
	if Q == P:
		return 1
		
	m = ceil(sqrt(P.order()))
	chunk_size = (m + num_processes - 1) // num_processes
	
	# Precompute the lookup table (baby steps) using multiple processes
	queue = multiprocessing.Queue()
	processes = [
			multiprocessing.Process(target=compute_baby_steps, args=(i * chunk_size, min((i + 1) * chunk_size, m), P, queue))
			for i in range(num_processes)
	]
	
	for p in processes:
			p.start()
	
	lookup_table = {}
	for _ in range(num_processes):
			lookup_table.update(queue.get())
	
	for p in processes:
			p.join()
	
	# Compute the giant steps in parallel
	processes = [
			multiprocessing.Process(target=compute_giant_steps, args=(i * chunk_size, min((i + 1) * chunk_size, m), m, P, Q, lookup_table, queue))
			for i in range(num_processes)
	]
	
	for p in processes:
			p.start()
	
	result = None
	for _ in range(num_processes):
			res = queue.get()
			if res is not None:
					result = res
					break
	
	for p in processes:
		p.terminate()
	
	return result

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
	io = remote("localhost", 8001)
	# io = process(["python3", "chall.py"]) # local testing

	io.recvuntil(b"p = ")
	p = int(io.recvline().strip())
	io.recvuntil(b"a = ")
	a = int(io.recvline().strip())
	io.recvuntil(b"b = ")
	b = int(io.recvline().strip())

	E = EllipticCurve(GF(p), [a, b])
	print(f"{p = } \n{a = } \n{b = }")
	print(E) # y^2 = x^3 + ax + b
	
	io.recvuntil(b"G = ")
	G = E(eval(io.recvline().strip()))
	print("G =",G.xy()) # G = (x, y)

	for i in range(10): # 10 rounds
		print("Round", i+1)
		io.recvuntil(b"G*x = ")
		xG = E(eval(io.recvline().strip()))
		print("G*x =", xG.xy())
		io.recvuntil(b"Enter x: ") # Enter x:
		x = bsgs_ecdlp(G, xG, E, 12)
		print("Found x:", x)
		io.sendline(str(x).encode())
		print(io.recvline()) # Correct, next round! or Congratulations! You have solved all 10 rounds!
	
	key = io.recvline().strip() # bytes
	print("Key:", key)
	decrypt(key, "encrypted.enc", "decrypted.pdf")
	io.close()
