#!/usr/bin/env python3

string = "label"
new_string = ""

for i in string:
    x = ord(i) ^ 13
    new_string += chr(x)

print('crypto{' + new_string +'}')

