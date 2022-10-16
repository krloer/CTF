f = open("challenge.txt", "r")

i = 0
maze = []
words = []
for line in f:
    if 0 < i < 46:
        maze.append(line.strip().replace(" ", ""))
    if i > 48:
        words.append(line.strip())
    i += 1

removals = []

word = "AGAINST"
ps = []
for line in maze:
    for j in range(len(line)):
        if word[0] == line[j]:
            ps.append([[word[0], maze.index(line), j]])

for i in range(1, len(word)):
    print(i)
    new = []
    turns = 0
    for pos in ps:
        last = pos[-1]
        found = 0
        print(word[i])
        if last[1]+1 <= 44:
            if maze[last[1]+1][last[2]] == word[i]:
                if [word[i], last[1]+1, last[2]] not in pos:
                    print([word[i], last[1]+1, last[2]])
                    print(pos)
                    pos.append([word[i], last[1]+1, last[2]])
                    found += 1
        if last[1]-1 >= 0:
            if maze[last[1]-1][last[2]] == word[i]:
                if [word[i], last[1]-1, last[2]] not in pos:
                    pos.append([word[i], last[1]-1, last[2]])
                    found += 1
        if last[2]+1 <= 44:
            if maze[last[1]][last[2]+1] == word[i]:
                if [word[i], last[1], last[2]+1] not in pos:
                    pos.append([word[i], last[1], last[2]+1])
                    found += 1
        if last[2]-1 >= 0:
            if maze[last[1]][last[2]-1] == word[i]:
                if [word[i], last[1], last[2]-1] not in pos:
                    pos.append([word[i], last[1], last[2]-1])
                    found += 1
        if last[1] != 44 and last[2] != 44:
            if maze[last[1]+1][last[2]+1] == word[i]:
                if [word[i], last[1]+1, last[2]+1] not in pos:
                    pos.append([word[i], last[1]+1, last[2]+1])
                    found += 1
        if last[1] != 0 and last[2] != 0:
            if maze[last[1]-1][last[2]-1] == word[i]:
                if [word[i], last[1]-1, last[2]-1] not in pos:
                    pos.append([word[i], last[1]-1, last[2]-1])
                    found += 1
        if last[1] != 0 and last[2] != 44:
            if maze[last[1]-1][last[2]+1] == word[i]:
                if [word[i], last[1]-1, last[2]+1] not in pos:
                    pos.append([word[i], last[1]-1, last[2]+1])
                    found += 1
        if last[1] != 44 and last[2] != 44:
            if maze[last[1]+1][last[2]-1] == word[i]:
                if [word[i], last[1]+1, last[2]-1] not in pos:
                    pos.append([word[i], last[1]+1, last[2]-1])
                    found += 1

        start = pos[:i]
        if len(pos) > i+1:
            for j in range(found):
                new.append(start+pos[-j:-j+1])
        if len(pos) == i+1:
            new.append(pos)
        print(new)
    ps = new

print(ps)
