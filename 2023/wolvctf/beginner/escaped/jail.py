
print("Welcome to my `cat` program. Give me a string and I'll output it back.")
# code = input("Enter your string (with double quotes) >>> ")

import ast
code = "str(3+3)"
# if code[0] == '"' and code[-1] == '"' and all(ch != '"' for ch in code[1:-1]):
if True:
  compiled = compile('print("' + eval(code) + '")', "out", mode = "exec")
  exec(compiled)
