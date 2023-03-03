code = ["X","X","X","X","X","X","X"]

# (code[2] + -0x30) * 7 - (code[3] * 5 + -0xf0) == 3
# (code[6] + -0x30) * -0xb + (code[2] + -0x30) * 4 == 1

for x in range(0x30,0x7f):
  for y in range(0x30,0x7f):
    if (x + -0x30) * 7 - (y * 5 + -0xf0) == 3:
      for z in range(0x30,0x7f):
        if (z + -0x30) * -0xb + (x + -0x30) * 4 == 1:
          code[2] = chr(x)
          code[3] = chr(y)
          code[6] = chr(z)
          print("".join(code))

