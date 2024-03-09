from pwn import *

with open("flags", "r") as f:
    flags = [l.strip() for l in f.readlines()]

#flag = flags[0]
for i, flag in enumerate(flags):
    print(i)
    p = process("./unstringify")
    # p.recvuntil(b"Enter the flag:")
    for i in range(17):
        l = p.recvline()
        #log.info(f"{l=}")
    p.sendline(flag.encode())
    l = p.recvall()
    log.info(f"{l=}")

    if l.startswith(b"Enter the flag: \nWrong flag"):
        continue

    p.interactive()

