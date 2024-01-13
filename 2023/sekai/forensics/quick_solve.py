from pwn import * 

p = remote("chals.sekai.team", 9000)

p.recvuntil(b"flag :)\n")
p.recvline()
task = p.recvline().decode()
a = int(task.split(" ")[0])
op = task.split(" ")[1]
b = int(task.split(" ")[2])
res = 0
if op == "+":
    res = a + b
elif op == "-":
    res = a - b
elif op == "/":
    res = a / b
elif op == "*":
    res = a * b
p.sendline(str(res).encode())

for i in range(99):
    if i > 80: 
        print(i)
    fb = p.recvline().decode()
    if fb != "correct\n":
        break
    task = p.recvline().decode()
    try:
        a = int(task.split(" ")[0])
        op = task.split(" ")[1]
        b = int(task.split(" ")[2])
        res = 0
        if op == "+":
            res = a + b
        elif op == "-":
            res = a - b
        elif op == "/":
            res = a / b
        elif op == "*":
            res = a * b
        p.sendline(str(res).encode())
    except:
        print(task)
        p.sendline(b"k")
        print(i)
        continue

p.interactive()