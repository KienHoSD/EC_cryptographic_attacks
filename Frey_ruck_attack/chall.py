from sage.all_cmdline import *
from Crypto.Util.number import *
from Crypto.Cipher import AES

def get_embedding_degree(q, n, max_k):
    for k in range(1, max_k + 1):
        if q ** k % n == 1:
            return k
    return None

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
        p = getPrime(128)
        a = p-1
        b = 0
        E = EllipticCurve(GF(p), [a, b])
        # print(prime_factors(E.order()))
        if prime_factors(E.order())[-1] <= 2**50 and 4*a**3 + 27*b**2 != 0: 
            for _ in range(10):
                G = E.random_point()
                k = get_embedding_degree(E.base_ring().order(), G.order(), 6)
                if(k != None):
                    return p, a, b, G
                

if __name__ == "__main__":
    p, a, b, G = gen_curve()
    E = EllipticCurve(GF(p), [a, b])
    key = randint(1, G.order() - 1)
    d = key
    P = G * d

    print(f'{p = }')
    print(f"{a = }")
    print(f"{b = }")
    print(f"G =", G.xy())
    print(f"P =", P.xy())
    encrypt(int.to_bytes(key, 16,"big"),"3-540-48910-X_14.pdf")