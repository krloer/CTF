check = "xk|nF{quxzwkgzgwx|quitH"
key = ""

for c in check:
    for g in range(64,127):
        a = (g + 65) % 122
        if a < 65:
            a += 61
        b = (a + 65) % 122
        if b < 65:
            b += 61
        if b == ord(c):
            key += chr(g)
            print(key)
            break

print(key)
