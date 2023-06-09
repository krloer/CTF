ins = ""
while len(ins) != 20:
  ins = input("input a string of size 20: ")

s = 0
a = 0
x = 0
y = 0
for c in ins:
  if c == 'r': # rev
    s += 1
  elif c == 'L': # left
    a = (a + 1) % 4
  elif c == 'R': # right
    a = (a + 3) % 4
  else:
    print("this character is not necessary for the solution.")
  if a == 0:
    print(f"going right by {s}")
    x += s
  elif a == 1:
    print(f"going up by {s}")
    y += s
  elif a == 2:
    print(f"going left by {s}")
    x -= s
  elif a == 3:
    print(f"going down by {s}")
    y -= s
print((x, y))
if x == 168 and y == 32:
  print("flag{" + ins + "}")
else:
  print("incorrect sadly")