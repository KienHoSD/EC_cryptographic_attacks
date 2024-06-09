from hashlib import sha1
from Crypto.Random.random import randint
from Crypto.Util.number import *
from ecdsa import SECP256k1 as secp256k1
from pwn import process, remote

# helper function to sign the commander message
def sign_commander_message(message, k = 0):
  e = int.from_bytes(sha1(message.encode()).digest(), byteorder='big')
  z = int.from_bytes(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'), byteorder='big')
  if k == 0:
    k = randint(1, n-1)
  C = G * k
  r = C.x() % n
  s = (z + r * d) * pow(k, n-2, n) % n
  return (int(r), int(s))

# io = process(['python3','chall.py']) for local testing
io = remote('localhost', 6060)

# We need to forge a signature for the message: '{"from": "Commander", "to": "Soldier", "message":"Give me the secret documents!"}'
# received the leaked messages and signatures
message1 = io.recvline().strip().decode()
r1, s1 = eval(io.recvline().split(b':')[-1].decode())
message2 = io.recvline().strip().decode()
r2, s2 = eval(io.recvline().split(b':')[-1].decode())

# Calculate the hash of the messages
e1 = int.from_bytes(sha1(message1.encode()).digest(), byteorder='big')
z1 = int.from_bytes(e1.to_bytes((e1.bit_length() + 7) // 8, byteorder='big'), byteorder='big')
e2 = int.from_bytes(sha1(message2.encode()).digest(), byteorder='big')
z2 = int.from_bytes(e2.to_bytes((e2.bit_length() + 7) // 8, byteorder='big'), byteorder='big')

# We can calculate d using the following formula:
G = secp256k1.generator
n = int(G.order())
r_inv = inverse(r1, n)
d = ((inverse(s1 - s2, n) * (z1 * s2 - z2 * s1) % n) * r_inv) % n

print("Found d: ", d)

forge_message = '{"from": "Commander", "to": "Soldier", "message":"Give me the secret documents!"}' # This is the message we want to forge
forge_signature = sign_commander_message(forge_message) # This is the signature of the message we want to forge

# Send the forged message and signature
io.sendline(forge_message)
io.sendlineafter('Enter r: ', str(forge_signature[0]).encode())
io.sendlineafter('Enter s: ', str(forge_signature[1]).encode()) 
io.interactive()