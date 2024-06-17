from sage.all import *
from Crypto.Util.number import getPrime, isPrime, bytes_to_long
from Crypto.Cipher import AES

def pad(data, block_size):
    return data + bytes([block_size - len(data) % block_size] * (block_size - len(data) % block_size))

def encrypt(key, filein, fileout):
    with open(filein, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    with open(fileout, 'wb') as f:
        f.write(cipher.encrypt(pad(data,16)))
    print(f"Encrypted file {filein} to file {fileout}")

def getPp1(x, k):
    while True:
        a = 4
        for _ in range(k):
            a *= getPrime(x // k)
        p = a - 1
        if isPrime(p):
            return p

if __name__ == "__main__":
    secret = os.urandom(32) # also the key to encrypt pdf file
    p, q = getPp1(512, 16), getPp1(512, 16)

    assert isPrime(p) and isPrime(q)
    n = p * q
    a, b = matrix(ZZ, [[p, 1], [q, 1]]).solve_right(
        vector([p**2 - p**3, q**2 - q**3])
    )
    E = EllipticCurve(Zmod(n), [a, b])
    G = E(p, p) + E(q, q)
    Q = bytes_to_long(secret) * G

    print(f"{p = }")
    print(f"{q = }")
    print(f"{a = }")
    print(f"{b = }")
    print(f"C =", Q.xy())
    print(f'{n = }')
    encrypt(secret, "2018-307.pdf", "encrypted.enc")

