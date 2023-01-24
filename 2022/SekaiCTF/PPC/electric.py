import sys
import math

radius = 0
available = 0
layers = []
length = 0
width = 0
onumber = 0
obstacles = []
lnumber = 1


for line in sys.stdin:
    if (lnumber == 1):
        input = line.split()
        radius = input[0]
        available = input[1]
        lnumber += 1
    elif (lnumber == 2):
        input = line.split()
        for t in input:
            layers.append(int(t))
        lnumber += 1
    elif (lnumber == 3):
        input = line.split()
        length = input[0]
        width = input[1]
        onumber = input[2]
        lnumber += 1
    elif (lnumber == 4):
        input = line.split()
        for i in range(int(len(input)/3)):
            obj = [input[i*3], input[i*3+1], input[i*3+2]]
            obstacles.append(obj)
        lnumber += 1
    else:
        break

print("Info:")
radius = int(radius)
available = int(available)
length, width = int(length), int(width)
onumber = int(onumber)
print(radius)
print(available)
print(layers)
print(length, width)
print(onumber)
print(obstacles)
print("\nCalculate:")

required_clearing = width
print(required_clearing)

for obs in obstacles:
    x, y, z = int(obs[0]), int(obs[1]), int(obs[2])
    low_clear = (y - z)
    high_clear = width - (y + z)
    clear = min(low_clear, high_clear)
    required_clearing = min(required_clearing, clear)

print(required_clearing)

if onumber > 1:
    for obs1 in obstacles:
        x1, y1, z1 = int(obs1[0]), int(obs1[1]), int(obs1[2])
        for obs2 in obstacles:
            x2, y2, z2 = int(obs2[0]), int(obs2[1]), int(obs2[2])
            if x2 == x1 and y2 == y1:
                continue
            if x2 == x1:
                distance = abs(y2-y1)
            elif (y2 == y1):
                distance = abs(x2-x1)
            else:
                distance = (abs(x2-x1)**2)+(abs(y2-y1)**2)
                distance = math.sqrt(distance)
            distance = distance - z1 - z2
            required_clearing = min(required_clearing, distance)

print(required_clearing)

added = 0
if (radius*2 >= required_clearing):
    added = -1
else:
    for i in range(len(layers)):
        radius += layers[i]
        if (radius*2 >= required_clearing):
            break
        else:
            added += 1

print(added)