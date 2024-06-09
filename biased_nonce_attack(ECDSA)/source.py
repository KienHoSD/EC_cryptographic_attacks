from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
from ecdsa.ecdsa import generator_256, Public_key, Private_key
from random import randint
from Crypto.Cipher import AES

G = generator_256
q = G.order()

FLAG = b'test_flag{NhatProVip}'


def encrypt_flag(privkey):
    cipher = AES.new(sha1(str(privkey.secret_multiplier).encode()).digest()[:16], AES.MODE_ECB)
    return cipher.encrypt(pad(FLAG, 16)).hex()

def genKeyPair():
    d = randint(1,q-1)
    pubkey = Public_key(G, d*G)
    privkey = Private_key(pubkey, d)
    return pubkey, privkey


def ecdsa_sign(msg, privkey):
    hsh = sha1(msg.encode()).digest()
    nonce = sha1(long_to_bytes(privkey.secret_multiplier) + hsh).digest()
    sig = privkey.sign(bytes_to_long(hsh), bytes_to_long(nonce))
    return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}



pubkey, privkey = genKeyPair()
encrypted_flag = encrypt_flag(privkey)

sig1 = ecdsa_sign("I have hidden the secret flag as a point of an elliptic curve using my private key.", privkey)
sig2 = ecdsa_sign("The discrete logarithm problem is very hard to solve, so it will remain a secret forever.", privkey)
sig3 = ecdsa_sign("Good luck!", privkey)

print('Encrypted flag:', encrypted_flag)
print('\nPublic key:', (int(pubkey.point.x()), int(pubkey.point.y())), '\n')
print(sig1)
print(sig2)
print(sig3)
