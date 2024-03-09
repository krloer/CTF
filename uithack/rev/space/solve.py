enc = ['x', 'D', 'y', 'e', 'L', 'N', 'F', 31, 25, 'V', 'z', 'E', 30, '_', 30, 'r', 28, 24, 'r', '@', 'T', 'r', 'N', 'X', ']', 'r', 29, 'K', 'r', 'G', 25, '[', 25, 18, 'P']
flag = ""

for c in enc:
    if type(c) == str:
        flag += chr(ord(c) ^ ord("-"))
    else:
        flag += chr(c ^ ord("-"))

print(flag)