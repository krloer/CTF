from pwn import *
import random
import string
import binascii
import os

print("Brute forcing...")

with open("enc", "rb") as f:
    enc = f.read()

def create_key():
    s=os.urandom(12)
    random.seed(s)
    key = ''
    for i in range(10):
        key += random.choice(string.ascii_lowercase)
    return binascii.hexlify(key.encode())

while True:
    chk = create_key()
    flag = xor(chk, enc)
    if b"UDCTF{" in flag:
        print(flag, chk)

# UDCTF{X0R_i5_th3_b35t} - guessed from outputs...