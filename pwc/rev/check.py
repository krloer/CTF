code = list("X"*7)

# 7*(x-48) - (5y - 240) = 3
# -11*(z-48) + 4*(x - 48) = 1

for x in range(0x20,0x7f):
  for y in range(0x20,0x7f):
    if 7 * (x - 48) - (5 * y - 240) == 3:
      for z in range(0x20,0x7f):
        if -11 * (z - 48) + 4* (x - 48) == 1:
          code[2] = chr(x)
          code[3] = chr(y)
          code[6] = chr(z)
          print("".join(code))

