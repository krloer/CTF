from PIL import Image

WIDTH = 1200
HEIGHT = 90

cyan = (0,255,255)
blue = (0,0,255)
red = (255,0,0)
magenta = (255,0,255)
green = (0,255,0)
yellow = (255,255,0)
black = (0,0,0)
white = (255,255,255)
gray = (128,128,128)


line1 = [blue, cyan, red, green, red, green, blue, cyan, red, green, red, green, black, gray,
blue, cyan, yellow, blue, magenta, red, blue, cyan, blue, cyan, gray, black,
cyan, magenta, red, magenta, magenta, red, red, magenta, cyan, magenta, gray, black, gray, black
]

line2 = [magenta, red, yellow, magenta, magenta, yellow, magenta, red, yellow, blue, yellow, magenta, white, black,
magenta, red, green, cyan, green, yellow, magenta, red, yellow, magenta, white, black,
red, blue, green, yellow, green, yellow, green, yellow, red, green, white, black, white, black
]

line3 = [green, yellow, blue, cyan, blue, cyan, yellow, green, cyan, magenta, blue, cyan, gray, white,
yellow, green, magenta, red, blue, cyan, yellow, green, red, green, gray, white,
green, yellow, blue, cyan, blue, cyan, blue, cyan, blue, yellow, gray, white, gray, white
]

im = Image.new("RGB", (WIDTH,HEIGHT))

for y in range(30):
    for x in range(WIDTH):
        colors = line1[int(x/30)]
        im.putpixel((x,y), colors)

for y in range(30,60):
    for x in range(WIDTH):
        colors = line2[int(x/30)]
        im.putpixel((x,y), colors)

for y in range(60,90):
    for x in range(WIDTH):
        colors = line3[int(x/30)]
        im.putpixel((x,y), colors)

im.save("mc86.png")
