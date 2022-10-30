from PIL import Image

divisors = [1, 2, 4, 5, 7, 8, 10, 14, 16, 20, 25, 28, 32, 35, 40, 50, 56, 64, 70, 80, 100, 112, 128, 140, 160, 175, 200, 224, 280, 320, 350, 400, 448, 560, 640, 700, 800, 896, 1120, 1400, 1600, 2240, 2800, 3200, 4480, 5600, 11200, 22400]

for a in divisors:
    WIDTH = a
    HEIGHT = int(22400/a)

    i = 0
    data = []
    f = open("converted.txt", "r")

    for line in f:
        data.append(line.strip())

    im = Image.new("RGB", (WIDTH,HEIGHT))

    for x in range(WIDTH):
        for y in range(HEIGHT):
            colors = data[i][1:-1].replace(" ", "").split(",")
            im.putpixel((x,y), (int(colors[0]), int(colors[1]), int(colors[2])))
            i += 1

    print(i)
    im.show()

#ninja{5QL_15_s000_fun!}