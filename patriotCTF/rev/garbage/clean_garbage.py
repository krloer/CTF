import string 
from random import * 

def finalstage(inp): 
    print("starting final stage stuff:")
    print(inp)
    print("")
    i=0 
    inp = list(inp) 
    inp.reverse() 
    inp = "".join(g for g in inp) 
    print(inp)
    flag = 'flag'.replace('flag', 'galf').replace('galf', '') # flag is just an empty string
    while i < len(inp): 
        try: 
            flag += inp[i+1] + inp[i] 
        except: 
            flag += inp[i] 
        i+=2 
    print(flag)
    print("Final Stage complete") 
    print("")
    return flag 

def stage2(flag): 
    f = "++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++.++++++.-----------.++++++."[-15:(7*9)].strip('-') # f is just an empty string
    print("Stage 2 stuff:")
    print(flag)
    print("")
    for q in range(len(flag)): 
        f += chr(ord(flag[q])-randint(0,5)) 
    print(f)
    print("Stage 2 complete") 
    print("")
    flag = finalstage(f) 
    return flag 

def stage1(flag): 
    print("")
    print("starting stage 1")
    print(flag)
    flag = list(flag) 
    lower_ascii = list(string.ascii_lowercase) 
    for i in range(len(flag)): 
        flag[i] = chr(ord(flag[i])^i) 
    f = "".join(x for x in flag) 

    print(f)
    for i in range(len(f)): 
        lower_ascii[i%len(lower_ascii)] = chr((ord(f[i])^ord(flag[i]))+len(lower_ascii))  # this does nothing to f
    print("Stage 1 complete: " + f)
    print("")
    flag = stage2(f) 
    return flag 

def entry(f): 
    seed(10) 
    f = list(f) 
    f.reverse() 
    f = "".join(i for i in f) 
    print("Entry complete: " + f) 
    flag = stage1(f) 
    return flag 

if __name__ == '__main__':
    input = entry(input("Enter Flag: ")) 
    flag = open('output.txt', 'r').readlines()[0] 
    print("Checking...")
    print(input)
    print(flag)
    if input == flag: 
        print("What... how?") 
        print("I guess you broke my 'beautiful' code :(") 
    else: 
        print("haha, nope. Try again!") 


