f = open("res.txt", "r")

flag = ""
for line in f:
    if len(line.strip()) == 1:
        flag += line.strip()

print(flag)

