from sage.all import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from secret import key

assert type(key) == int # check if key is an integer

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
        p = getPrime(64)
        a = p-1
        b = 0
        E = EllipticCurve(GF(p), [a, b])
        if 4 * a ** 3 + 27 * b ** 2 != 0 and abs(p - E.order()) < 20: # trace of Frobenius is small with small order to calculate faster
            return p, a, b

if __name__ == "__main__":
    p, a, b = gen_curve()
    E = EllipticCurve(GF(p), [a, b])
    G = E.random_point()
    d = key
    assert G.order() > d, "G order not bigger than d" # check if the order is greater than d (key)
    P = G * d

    print(f'{p = }')
    print(f"{a = }")
    print(f"{b = }")
    print(f"G =", G.xy())
    print(f"P =", P.xy())
    encrypt(int.to_bytes(key, 16),"3-540-48910-X_14.pdf")