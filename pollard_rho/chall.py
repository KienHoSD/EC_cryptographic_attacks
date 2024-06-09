from sage.all import *
from Crypto.Cipher import AES 
from Crypto.Util.number import isPrime, getPrime
from Crypto.Util.Padding import pad
from hashlib import sha1
import random


def pad(data, block_size):
    return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(key, filein, fileout):
    with open(filein, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    with open(fileout, 'wb') as f:
        f.write(cipher.encrypt(pad(data,16)))
    print(f"Encrypted file {filein} to file {fileout}")	

def genPara():
    while True:
        p = getPrime(32)
        a,b = random.randrange(0,p-1), random.randrange(0,p-1)
        E = EllipticCurve(GF(p), [a,b])
        if (4*a**3 + 27 * b**2) % p != 0 and isPrime(int(E.order())): # make sure it's not a singular curve
            return p,a,b

if __name__ == "__main__":
    print("Welcome to Elliptic Curve Cryptography!!!")
    print("We are going to encrypt the content of Project.pdf using Elliptic Curve Cryptography.")
    print("Please wait a moment, we are generating parameters for Elliptic Curve...")
    
    p,a,b = genPara()
    F = GF(p)
    E = EllipticCurve(F, [a,b])
    P = E.gens()[0] 
    secret = random.randint(0,p-1)
    Q = P * secret

    print(f'{a = }')
    print(f'{b = }')
    print(f'{p = }')
    print('P =', P.xy())
    print('Q =', Q.xy())
    
    encrypt(int.to_bytes(secret, 16), 'Project.pdf', "encrypted.enc")