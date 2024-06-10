from sage.all import *
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
import random
from secret import key

assert len(key) == 16
assert type(key) == bytes

def pad(data, block_size):
    return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(key, filein):
    with open(filein, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    with open('encrypted.enc', 'wb') as f:
        f.write(cipher.encrypt(pad(data,16)))
    print(f"Encrypted {filein} with key")	

def gen_curve():
	while True:
		p = getPrime(32) # 32-bit prime
		a = randint(1, p-1)
		b = randint(1, p-1)
		try:
			E = EllipticCurve(GF(p), [a, b])
			if (4*a**3 + 27*b**2) % p == 0 or not is_prime(E.order()): # singular curve or curve not prime order will cause error, so we skip them
				continue
			return p,a,b
		except ArithmeticError:
			pass

def welcome():
	print("Welcome to the Elliptic Curve Discrete Logarithm Problem!")
	print("You will be given a curve E over a finite field F_p, and a point G on E.")
	print("You will be asked to compute G*x for a random x, and you need to enter x.")
	print("If G*x = (x, y), you need to enter x.")
	print("If G*x is not a valid point on E, you will be given another chance.")
	print("If you enter the wrong x, the program will terminate.")
	print("We will handout the key if you can solve 10 rounds.")
	print("Good luck!\n")

if __name__ == "__main__":
	encrypt(key, "2015-605.pdf")
	welcome()
	p, a, b = gen_curve()
	E = EllipticCurve(GF(p), [a, b])
	print(f"{p = } \n{a = } \n{b = }")
	try:
		G = E.random_point()
		print(f"G = {G.xy()}")
		for i in range(10): # 10 rounds
			x = random.randint(1, E.order())
			print("G*x =", (G*x).xy())
			x_input = int(input("Enter x: "))
			if(G*x == G*x_input):
				if(i == 9):
					print("Congratulations! You have solved all 10 rounds!")
					print(key.decode())
					break
				print("Correct, next round!")
			else:
				print("Wrong, bye!")
				break
	except Exception as e:
		print(e)
		print("[-] Something's wrong!")