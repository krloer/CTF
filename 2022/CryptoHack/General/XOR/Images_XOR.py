#!/usr/bin/env python3

from PIL import Image
from pwn import *

f1 = Image.open("flag_7ae18c704272532658c10b5faad06d74.png") #f1 is an image, not png file, XORing PNG files will almost never return a PNG file
f2 = Image.open("lemur_ed66878c338e662d3473f0d98eedbd0d.png")

flagbts = xor(f1.tobytes(), f2.tobytes())
flag = Image.frombytes(f1.mode, f1.size, flagbts)

flag.show()






