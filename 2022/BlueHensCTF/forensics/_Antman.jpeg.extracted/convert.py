import base64

i = open("could_this_be_it.txt", "r")
o = open("converted.txt","w")

for line in i:
    conv = base64.b64decode(line)
    o.write(conv.decode())

