from sage.all import *
from Crypto.Util.number import *
from pwn import *
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

# from jvdsn 
def get_embedding_degree(q, n, max_k):
    """
    Returns the embedding degree k of an elliptic curve.
    Note: strictly speaking this function computes the Tate-embedding degree of a curve.
    In almost all cases, the Tate-embedding degree is the same as the Weil-embedding degree (also just called the "embedding degree").
    More information: Maas M., "Pairing-Based Cryptography" (Section 5.2)
    :param q: the order of the curve base ring
    :param n: the order of the base point
    :param max_k: the maximum value of embedding degree to try
    :return: the embedding degree k, or None if it was not found
    """
    for k in range(1, max_k + 1):
        if q ** k % n == 1:
            return k

    return None

def attack(P, R, max_k=6, max_tries=10):
    """
    Solves the discrete logarithm problem using the Frey-Ruck attack.
    More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 3)
    :param P: the base point
    :param R: the point multiplication result
    :param max_k: the maximum value of embedding degree to try (default: 6)
    :param max_tries: the maximum amount of times to try to find l (default: 10)
    :return: l such that l * P == R, or None if l was not found
    """
    E = P.curve()
    q = E.base_ring().order()
    n = P.order()
    assert gcd(n, q) == 1, "GCD of base point order and curve base ring order should be 1."

    logging.info("Calculating embedding degree...")
    k = get_embedding_degree(q, n, max_k)
    if k is None:
        return None

    logging.info(f"Found embedding degree {k}")
    Ek = E.base_extend(GF(q ** k))
    Pk = Ek(P)
    Rk = Ek(R)
    for _ in range(max_tries):
        S = Ek.random_point()
        T = Ek.random_point()
        if (gamma := Pk.tate_pairing(S, n, k) / Pk.tate_pairing(T, n, k)) == 1:
            continue

        delta = Rk.tate_pairing(S, n, k) / Rk.tate_pairing(T, n, k)
        logging.info(f"Computing {delta}.log({gamma})...")
        l = delta.log(gamma)
        return int(l)

    return None

def unpad(data, block_size):
    return data[:-data[-1]]

def decrypt(d, file):
    with open(file, 'rb') as f:
        data = f.read()
    cipher = AES.new(d.to_bytes(16, 'big'), AES.MODE_ECB)
    with open(file + '.restore.pdf', 'wb') as f:
        f.write(unpad(cipher.decrypt(data),16))

r = remote("localhost", 6070)
# r = process(["python3", "chall.py"])

p = int(r.recvlineS().split('=')[1].strip())
a = int(r.recvlineS().split('=')[1].strip())
b = int(r.recvlineS().split('=')[1].strip())
G = eval(r.recvlineS().split('=')[1].strip())
P = eval(r.recvlineS().split('=')[1].strip())
print(r.recvline())

print(f'{p = }')
print(f"{a = }")
print(f"{b = }")
print(f"G =", G)
print(f"P =", P)


E = EllipticCurve(GF(p), [a, b])
G = E(G)
P = E(P)
print("Order:", E.order())

d = attack(G, P)
assert G*d == P, "wrong d!" # check if d is correct, have chance to fail
print("d:", d)

decrypt(d, "3-540-48910-X_14.pdf.enc")
print("Decrypted!")
