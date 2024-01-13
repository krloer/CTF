lines = []
with open("flag.txt") as f:
    for line in f.readlines():
        lines.append(line.strip())

lines = lines[2:]

print("".join(lines[::-1]))