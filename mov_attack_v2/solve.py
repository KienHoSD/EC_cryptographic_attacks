from sage.all import *
from pwn import remote, process
from Crypto.Cipher import AES

def unpad(data, block_size):
    return data[:-data[-1]]

def decrypt(key, filein, fileout):
    with open(filein, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_ECB)
    with open(fileout, 'wb') as f:
        f.write(unpad(cipher.decrypt(data),16))
    print(f"Decrypted file {filein} to file {fileout}")

def mov_attack(E, P, G):
    k = 2
    p = E.base_ring().characteristic()
    K = GF(p**k, "a")
    EK = E.base_extend(K)
    PK = EK(P)
    GK = EK(G)
    QK = EK.random_point()  # Assuming QK is linear independent to PK
    egqn = PK.tate_pairing(QK, E.order(), k)  # e(P,Q)=e(G,Q)^n
    egq = GK.tate_pairing(QK, E.order(), k)  # e(G,Q)
    odr = ZZ(pari.fforder(egq, p + 1))
    lg = ZZ(pari.fflog(egqn, egq, odr))
    return lg, odr

if __name__ == "__main__":
    io = remote("localhost", 8004)
    # io = process(["python3", "chall.py"]) # local testing

    p = int(io.recvlineS().split('=')[1].strip())
    q = int(io.recvlineS().split('=')[1].strip())
    a = int(io.recvlineS().split('=')[1].strip())
    b = int(io.recvlineS().split('=')[1].strip())
    C = eval(io.recvlineS().split('=')[1].strip())
    n = int(io.recvlineS().split('=')[1].strip())

    print(f"{p = }")
    print(f"{q = }")
    print(f"{a = }")
    print(f"{b = }")
    print(f"C =", C)
    print(f'{n = }')

    E = EllipticCurve(Zmod(n), [a, b])
    G = E(p, p) + E(q, q)
    Ep = E.change_ring(Zmod(p))
    Eq = E.change_ring(Zmod(q))

    mp, op = mov_attack(Ep, Ep(C), Ep(G))
    mq, oq = mov_attack(Eq, Eq(C), Eq(G))
    secret = int(crt([mp, mq], [op, oq])) # convert Integer to int

    decrypt(int.to_bytes(secret, 16), "encrypted.enc", "decrypted.pdf")
    