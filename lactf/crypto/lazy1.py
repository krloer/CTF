from pwn import *

r = remote("lac.tf", 31110)

p = int(r.recvline())
q = int(r.recvline())

n=p*q
modulo=n+1

r.recvuntil(b">>")
r.sendline(b"1")
r.recvuntil(b"modulus here:")
r.sendline(str(modulo).encode())
result = int(r.recvline().decode().strip())

r.recvuntil(b">>")
r.sendline(b"2")
r.recvuntil(b"guess here:")
r.sendline(str(result).encode())


r.interactive()
