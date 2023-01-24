from more_itertools import first
from pwn import * 

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

f = open("jokes.txt", "r")
jokes = []

for line in f:
    line = line.upper()
    for c in line:
        if c not in ALPHABET:
            line = line.replace(c, "")
    jokes.append(line)

def firstjoke(length):
    for joke in jokes:
        if len(joke) == length:
            return joke

def secondjoke(correct, firstguess):
    for joke in jokes:
        if joke == firstguess:
            continue
        failed = 1
        if len(joke) == len(firstguess):
            failed = 0
            for chk in correct:
                if joke[chk[0]] == chk[1]:
                    continue
                else: 
                    failed = 1
                    break
        if failed==0:
            return joke
    return print("No match")

p = remote("0.cloud.chals.io", 33282)

p.recvline()
for i in range(10):
    print(p.recvuntil(b"Your joke is "))

    firstguess = ""
    secondguess = ""
    correct = []
    length = ""
    feedback = ""
    length = int(p.recvline().decode()[:2])
    p.recvline()
    print(length)
    firstguess = firstjoke(length)
    print(firstguess)

    p.sendline(firstguess.encode())
    p.recvuntil(b"'correct': [")
    feedback = p.recvuntil(b"]").decode()[:-1]
    feedback = feedback.split(", ")
    print(feedback)
    print(p.recv())

    correct = []
    if len(feedback) > 0:
        for c in feedback:
            one = [int(c), firstguess[int(c)]] #position, character
            correct.append(one)
    print(correct)

    secondguess = secondjoke(correct, firstguess)

    print(secondguess)
    p.sendline(secondguess.encode())
    print(p.recvline())
    print("---------------------------------------------" + str(i+1))

p.interactive()
print(p.recv())

#UDCTF{wh4ts_th3_be5t_th1ng_ab0ut_Sw1tzerl4nd? Dunn0_bu7_th3_flag_15_a_b1g_plu5!}
