from pwn import *

context.arch = "arm"

sc = shellcraft.arm.mov('r0', 0xdeadbeef)
sc += shellcraft.arm.itoa('r0')
sc += shellcraft.arm.linux.write(1, 'sp', 32)
assembly = asm(sc)

print(assembly)