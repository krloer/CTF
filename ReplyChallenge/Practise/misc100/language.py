m = open("maze.txt", "r")
ma = open("map.txt", "r")
maze = []
map = []
i = 0
l = -1

for line in m:
    maze.append(line)

for line in ma:
    if i % 6 == 0:
        map.append([])
        l += 1
    map[l].append(line.strip("\n"))
    i += 1

result = ""

for char in map:
    first = char[0]
    top = int(char[1])
    c = int(char[2])
    bot = int(char[3])
    second = char[4]

    firstline = ""
    middleline = ""
    secondline = ""
    for i in range(len(maze)):
        if first in maze[i]:
            if second in maze[i+top+bot]:
                firstline = maze[i]
                secondline = maze[i+top+bot]
                middleline = maze[i+top]
            break
    offset = firstline.index(first)
    result += middleline[offset+c]
    
print(result)

