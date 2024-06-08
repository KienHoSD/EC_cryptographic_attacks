from sage.all import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from secret import secret

def pad(data, block_size):
    return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(d, file):
    with open(file, 'rb') as f:
        data = f.read()
    cipher = AES.new(d.to_bytes(16, 'big'), AES.MODE_ECB)
    with open(file + '.enc', 'wb') as f:
        f.write(cipher.encrypt(pad(data,16)))
    print(f"Encrypted {file} with key d")

def gen_curve():
    while True:
        p = getPrime(64)
        a = p-1
        b = 0
        if 4 * a ** 3 + 27 * b ** 2 != 0 and abs(EllipticCurve(GF(p), [a, b]).order() - p) < 20: # trace of Frobenius is small with small order to calculate faster
            return p, a, b

p, a, b = gen_curve()
E = EllipticCurve(GF(p), [a, b])
G = E.random_point()
d = secret
P = G * d

print(f'{p = }')
print(f"{a = }")
print(f"{b = }")
print(f"G =", G.xy())
print(f"P =", P.xy())
encrypt(d,"3-540-48910-X_14.pdf")



