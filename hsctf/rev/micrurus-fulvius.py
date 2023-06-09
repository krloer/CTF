# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.16 (default, May 23 2023, 14:26:40) 
# [GCC 10.2.1 20210110]
# Embedded file name: chall.py
# Compiled at: 2023-06-01 21:33:44
# Size of source mod 2**32: 644 bytes
from hashlib import sha256

ALPH = "".join([chr(x) for x in range(0x21,0x7f)])

def a(n):
    b = 0
    while n != 1:
        if n & 1:
            n *= 3
            n += 1
        else:
            n //= 2
        b += 1

    return b

def d(u, p):
    return (u << p % 5) - 158

def j(q, w):
    return ord(q) * 115 + ord(w) * 21

def t(inp):
    x = inp
    l = [-153, 462, 438, 1230, 1062, -24, -210, 54, 2694, 1254, 69, -162, 210, 150]
    m = 'b4f9d505'
    # if len(x) - 1 != len(l):
    #     print("wrong length")
    #     return False
    for i, c in enumerate(zip(x, x[1:])):
        if d(a(j(*c) - 10), i) * 3 != l[i]:
            return False
    return True

def g():
    test = ""
    for b in range(0x21,0x7f):
        test = "flag{" + chr(b)
        if t(test):
            for c in range(0x21,0x7f):
                test1 = test + chr(c)
                if t(test1):
                    for e in range(0x21,0x7f):
                        test2 = test1 + chr(e)
                        if t(test2):
                            for f in range(0x21,0x7f):
                                test3 = test2 + chr(f)
                                if t(test3):
                                    for h in range(0x21,0x7f):
                                        test4 = test3 + chr(h)
                                        if t(test4):
                                            for i in range(0x21,0x7f):
                                                test5 = test4 + chr(i)
                                                if t(test5):
                                                    for k in range(0x21,0x7f):
                                                        test6 = test5 + chr(k)
                                                        if t(test6):
                                                            for l in range(0x21,0x7f):
                                                                test7 = test6 + chr(l)
                                                                if t(test7):
                                                                    for m in range(0x21,0x7f):
                                                                        test8 = test7 + chr(m)
                                                                        if t(test8):
                                                                            maybe = test8 + "}"
                                                                            if t(maybe):
                                                                                if sha256(maybe.encode()).hexdigest()[:8] == 'b4f9d505':
                                                                                    print(maybe)

if __name__ == '__main__':
    g()