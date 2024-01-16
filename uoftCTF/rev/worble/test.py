import dis

def shmorble(s):
    r = ''
    for i in range(len(s)):
        r += s[i-len(s)]
    return r

if __name__ == "__main__":
    s = "abcdefgh"
    shmorble(s)
    print(dis.dis(shmorble))