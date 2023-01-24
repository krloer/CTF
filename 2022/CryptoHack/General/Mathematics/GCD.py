#!/usr/bin/env python3

def gcd(a, b):
    while(a != 0):
        r = b%a
        b,a = a,r
    return b

print(gcd(52920, 66528))
