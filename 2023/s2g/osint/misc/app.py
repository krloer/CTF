#!/usr/bin/env python3

from flag import flag
from ast import literal_eval

def is_numeric(val):
    return type(val) in [int, float]

values = input('Input two numeric values [a, b] where a == b but str(a) != str(b): ')
a, b = [literal_eval(v) for v in values.split(' ')]
assert is_numeric(a) and is_numeric(b), 'a and b must be numeric!'
assert a == b, 'a must be equal to b!'
assert str(a) != str(b), 'str(a) must not be equal to str(b)!'

values = input('Input two values [a, b] where a - b > 1 but a + 1 == b + 1: ')
a, b = [literal_eval(v) for v in values.split(' ')]
assert a - b > 1, 'a - b must be greater than 1!'
assert a + 1 == b + 1, 'a + 1 must be equal to b + 1!'

values = input('Input two values [a, b] such that a > 0 and abs(a**b) != a**b: ')
a, b = [literal_eval(v) for v in values.split(' ')]
assert a > 0, 'a must be greater than 0!'
assert abs(a**b) != a**b, 'abs(a**b) must not be equal to a**b!'

print('Well done')
print(flag)
