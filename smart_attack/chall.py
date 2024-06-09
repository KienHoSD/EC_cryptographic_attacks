from sage.all_cmdline import *
from random import randint	
from Crypto.Cipher import AES
import json

# params from http://www.monnerat.info/publications/anomalous.pdf
D = 11
j = -2**15

def anom_curve():
    m = 257743850762632419871495
    p = (11*m*(m + 1)) + 3
    a = (-3*j * inverse_mod((j - 1728), p)) % p
    b = (2*j * inverse_mod((j - 1728), p)) % p
    E = EllipticCurve(GF(p), [a,b])
    return p, a, b, E

def smarts_attack():
	# with open("smarts_attack_curves.json",'r') as f:
	# 	curves = json.loads(f.read())
	# index = randint(0,len(curves)-1)
	# p = int(curves[index]['field']['p'],16)
	# a = int(curves[index]['a'],16)
	# b = int(curves[index]['b'],16)
	# E = EllipticCurve(GF(p), [a, b])
	p, a, b, E = anom_curve()
	print("The curve parameters are:")
	print("p = "+str(p))
	print("a = "+str(a))
	print("b = "+str(b))
	P1 = E.gens()[0]
	print('\nP1: '+str(P1.xy()))
	secret = randint(1, E.order() - 1)
	P2 = secret * P1
	print('P2: '+str(P2.xy()))
	print('P2 = secret * P1')
	return secret

def pad(data, block_size):
    return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(key, filein, fileout):
    with open(filein, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    with open(fileout, 'wb') as f:
        f.write(cipher.encrypt(pad(data,16)))
    print(f"Encrypted file {filein} to file {fileout}")	

def main():
	print("The answer will be a randomly generated solution and hence not an obvious message.")
	print("Are you smart enough to crack this?\n")
	smarts = smarts_attack()
	encrypt(smarts.to_bytes(32)[:16], "s001459900052.pdf", "encrypted.enc")
	while True:
		print("\nWhat is the value of 'secret'?: ")
		n = int(input(""))
		if n == smarts:
			print("Success!")
			break
		else:
			print("Please try again!")

if __name__ == "__main__":
	main()