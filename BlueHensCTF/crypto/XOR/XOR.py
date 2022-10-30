#!/usr/local/bin/python3.9
from pwn import *
import random
import string
import binascii
import os
s=os.urandom(12)
random.seed(s)

with open('flag.txt','r') as f:
    flag = f.read().encode()

def create_key():
    key = ''
    for i in range(10):
        key += random.choice(string.ascii_lowercase)
    return binascii.hexlify(key.encode())

k = create_key()

enc = xor(flag,k) # xors each byte

print(b'Decrypt this -> ' + enc)