import re
from itertools import product

def worble(s):
    s1 = 5
    s2 = 31
    for n in range(len(s)):
        s1 = (s1 + ord(s[n]) + 7) % 65521
        s2 = (s1 * s2) % 65521
    return s2 << 16 | s1

def shmorble(s):
    r = ''
    for i in range(len(s)):
        r += s[i-len(s)]
    return r

def blorble(a, b):
    return format(a, 'x') + format(b, 'x')

def check(flag):
    pattern = re.compile('^uoftctf\\{([bdrw013]){9}\\}$')
    # print('                      _     _             ')
    # print('                     | |   | |            ')
    # print('  __      _____  _ __| |__ | | ___ _ __   ')
    # print("  \\ \\ /\\ / / _ \\| '__| '_ \\| |/ _ \\ '__|  ")
    # print('   \\ V  V / (_) | |  | |_) | |  __/ |     ')
    # print('    \\_/\\_/ \\___/|_|  |_.__/|_|\\___|_|     ')
    # print('                                          ')
    # print('==========================================')
    # flag = input("Enter flag: ")
    if not pattern.match(flag):
        print(flag)
        print("Incorrect format")
        exit(0)
    a = worble(flag)
    b = worble(flag[::-1])
    # print("Here's your flag: " + shmorble(blorble(a,b)))
    return shmorble(blorble(a,b))

if __name__ == "__main__":
    possible = list("bdrw013")
    for i, contents in enumerate([''.join(i) for i in product(possible, repeat = 9)]):
        flag = "uoftctf{" + contents + "}"
        if check(flag) == "a81c0750d48f0750":
            print(f"CORRECT: {flag}")
            exit(0)
        if i % 1000000 == 0:
            print(i)
            print(flag)