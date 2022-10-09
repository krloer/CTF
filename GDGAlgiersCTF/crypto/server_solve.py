#!/usr/bin/env python3
from matplotlib.pyplot import flag
from pwn import *

def xor(enc, key):
    return ''.join([chr(e^k) for e,k in zip(enc, key)] )

payload = 128 * 'a'
start = 16 * b'a'

r = remote("crypto.chal.ctf.gdgalgiers.com", 1002)

print(r.recvuntil(b">> "))
r.sendline(payload)
enc = r.recvline()
enc = enc[2:-1].decode()

print(enc)


benc = bytes.fromhex(enc) # len 128
print(benc)

bstart = benc[:16]
startkey = xor(start, bstart).encode()
key = startkey*8
flagbytes = xor(payload.encode(), key)
print(flagbytes)
print(flagbytes.encode().hex())

r.close()