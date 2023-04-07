from PIL import Image

# Opens up image
image = Image.open("./Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png")
loaded = image.load()
im = image.convert("RGB")
dim = image.size
imgLength = dim[0]
imgHeight = dim[1]

# Blank string that reads the binary digits
string = ""

# Goes through each pixel top-down
for y in range(imgHeight):
    for x in range(imgLength):
        # Gets the RGB values of the pixel
        # r, g, b = loaded[x, y]
        r,g,b = im.getpixel((x,y))

        # Store the MSB of each color in a string
        string += str(int(r&128 != 0))
        string += str(int(g&128 != 0))
        string += str(int(b&128 != 0))


print("Loaded " + str(len(string)) + " bits")

# Converts binary to ASCII

print("".join([chr(int(string[i*8:i*8+8], 2)) for i in range(len(string)//8)]))
