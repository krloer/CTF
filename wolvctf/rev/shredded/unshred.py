order = [2, 4, 18, 31, 19, 21, 13, 5, 12, 30, 27, 28, 25, 9, 16, 6, 26, 24, 17, 29, 11, 14, 1, 3, 15, 7, 32, 0, 20, 23, 10, 8, 22]
lines = ["" for _ in range(39)]

for i in order:
    fname = "./shredFiles/shred" + str(i) + ".txt"
    with open(fname, "r") as f:
        for j, c in enumerate(f.read()):
            if j % 2 == 0:
                lines[round(j/2)] += c

for i in range(39):
    lines[i] += "\n"

with open("unshredded.c", "w") as file:
    file.writelines(lines)