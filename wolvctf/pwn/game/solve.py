from pwn import *

p = process("./chal")
# gdb.attach(p, gdbscript="""
# b *main+438
# c
# """)

# p.recvuntil(b">")
# p.sendline(b"-12\x00/bin/sh")

p.interactive()