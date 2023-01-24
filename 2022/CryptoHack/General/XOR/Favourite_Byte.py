#!/usr/bin/env python3
from pwn import xor

bytestring = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
for i in range(255):
    x = xor(bytestring, bytes([i]))
    print(x)
