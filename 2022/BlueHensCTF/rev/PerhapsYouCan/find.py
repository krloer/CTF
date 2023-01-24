import string
import random

def check(tmp):
    sum = ord(tmp[0]) * ord(tmp[1]) * ord(tmp[2])
    if sum == 615264:
        return True

chars = string.ascii_letters+string.digits
print(chars)
while True:
    test = "".join(random.choices(chars, k=3))
    if check(test):
        print(test)
