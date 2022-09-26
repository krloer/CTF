#!/usr/bin/env python3

from Crypto.Util.number import *

bigInteger = 0x637a5f6578706572746973655f686f74656c
print(long_to_bytes(bigInteger))
