from random import * 

def rev_stage1_entry(r):
    r = list(r)
    for i in range(len(r)): 
        r[i] = chr(ord(r[i])^i) 
    r.reverse()
    inp = "".join(x for x in r) 
    return inp

def rev_stage2(r):
    seed(10)
    inp = ""
    for q in range(len(r)): 
        inp += chr(ord(r[q])+randint(0,5)) 
    return inp

def rev_stage3(r):
    flag = ""
    i = 0
    while i < len(r): 
        try: 
            flag += r[i+1] + r[i] 
        except: 
            flag += r[i] 
        i+=2 

    flag = list(flag) 
    flag.reverse() 
    flag = "".join(g for g in flag) 
    return flag

def rev(r):
    r = rev_stage3(r)
    r = rev_stage2(r)
    r = rev_stage1_entry(r)
    print("reversed: " + r)

flag = open('output.txt', 'r').readlines()[0] 
rev(flag)