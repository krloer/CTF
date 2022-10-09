import os
import random

def xor(enc, key):
    return ''.join([chr(e^k) for e,k in zip(enc, key)] )

flagenc = "Kæ3 H½{ÑÙ1\x00åÉFYmï8âzfÇ\x1abÁÈ9~Oå"
enc = "$\x04ÿñ\x17Så7³l®oÔÑ"
input = b"aaaaaaaaaaaaaaaaaa"
c = xor(input,enc.encode()).encode()
print(c)
d = xor(c, flagenc.encode())
print(d)