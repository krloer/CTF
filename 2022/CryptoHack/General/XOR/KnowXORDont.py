#!/usr/bin/env python3
from pwn import xor

bytestring = bytes.fromhex('0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104')
print(bytestring)
key_start = "crypto{"
print(xor(key_start, bytestring)) #myXORke+y
key = "myXORkey"
print(xor(key, bytestring))


# flag = bytestring ^ key
# key = flag ^ bytestring