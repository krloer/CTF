sus = open("SEKAI.sus", "r")
less = open("lesssus.txt", "w")

for i in range(264):
    line = str(sus.readline())
    fixed = line.replace("0", "")
    print(line)
    less.write(fixed)
