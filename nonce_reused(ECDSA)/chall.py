from hashlib import sha1
from Crypto.Random.random import randint
from secret import secret_message
import json
from ecdsa import SECP256k1 as secp256k1

leaked_msg1_commander = '{"from": "Commander", "to": "Soldier", "message":"Good work, soldier. Return to base immediately. We will need to analyze the documents as soon as possible."}'
leaked_msg2_commander = '{"from": "Commander", "to": "Soldier", "message":"we will launch a surprise attack on the enemy base at dawn. Be prepared."}'

G = secp256k1.generator
n = int(G.order())
d = randint(1, n-1)
Q = G * d
k = randint(1, n-1)

def sign_commander_message(message, k = 0):
  e = int.from_bytes(sha1(message.encode()).digest(), byteorder='big')
  z = int.from_bytes(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'), byteorder='big')
  if k == 0:
    k = randint(1, n-1)
  C = G * k
  r = C.x() % n
  s = (z + r * d) * pow(k, n-2, n) % n
  return (int(r), int(s))

def verify_commander_signature(message, signature):
  if json.loads(message)['from'] != 'Commander':
    return False
  r, s = signature
  if not (0 < r < n and 0 < s < n):
    return False
  e = int.from_bytes(sha1(message.encode()).digest(), byteorder='big')
  z = int.from_bytes(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'), byteorder='big')
  u1 = z * pow(s, -1, n) % n
  u2 = r * pow(s, -1, n) % n
  C = G * u1 + Q * u2
  if C.x() % n == r:
    return True
  return False



print(leaked_msg1_commander)
commander_signature = sign_commander_message(leaked_msg1_commander, k)
print("signature:", commander_signature)
assert verify_commander_signature(leaked_msg1_commander, commander_signature)

print(leaked_msg2_commander)
commander_signature = sign_commander_message(leaked_msg2_commander, k)
print("signature:", commander_signature)
assert verify_commander_signature(leaked_msg2_commander, commander_signature)


enemy_message = input("Enter the message to sign: ")
enemy_r = int(input("Enter r: "))
enemy_s = int(input("Enter s: "))
enemy_signature = (enemy_r, enemy_s)

if verify_commander_signature(enemy_message, enemy_signature):
  if json.loads(enemy_message)['message'] == 'Give me the secret documents!':
    print("Yes sir!, Here is the secret:", secret_message)
    exit(0)
  else:
    print("What are you talking about Commander?")

print("You are not the real Commander!")
 
# The script is vulnerable to a nonce reuse attack. The script uses the same nonce for two different messages.
