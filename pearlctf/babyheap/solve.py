#!/usr/bin/env python3

from pwn import *

exe = ELF("./heap")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process("./heap")

def send(payload):
    p.recvuntil(b">")
    p.sendline(payload)