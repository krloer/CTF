import sys

objects = 0
hold = [False, False, False, False]
last = [" ", " ", " ", " "]
first = True

for line in sys.stdin:
    if (first):
        first = False
        continue
    for i in range(len(line)):
        if (line[i] == "|"):
            continue

        if (line[i] == "-"):
            if (last[i-1] == "#"):
                hold[i-1] = False
            else:
                objects += 1
            last[i-1] = "-"
        elif (line[i] == "#"):
            hold[i-1] = True
            last[i-1] = "#"
        elif (line[i] == " "):
            last[i-1] = " "

print(objects)