"""
This function takes in a (non-empty) list and moves the first element
of the list so it becomes the last element of the list
E.g. [1,2,3,4,5] -> [2,3,4,5,1]
"""
def move_list_element(mylist: list):
    # Write your code here
    mylist.append(mylist[0])
    return mylist[1:]


"""
This function takes in a dictionary.
If the dictionary contains the key "banana" increment it by 1.
Otherwise, add the key and set its value to 1
"""
def count_banana(mydict: dict):
    if "banana" in mydict.keys():
        mydict["banana"] += 1
    # Write your code here
    return mydict


"""
This function takes in a tuple.
Return a new tuple with the order of the items reversed
"""
def reverse_tuple(mytuple: tuple):
    # Write your code here
    return mytuple[::-1]


# Some optional tests to help you verify
mylist = [1, 2, 3, 4, 5]
print(f"{move_list_element(mylist)=} (Expected [2, 3, 4, 5, 1])")

mydict = {'apple':3,'banana':10,'orange':30}
print(f"{count_banana(mydict)=} (Expected {{'apple':3,'banana':11,'orange':30}})")

mytuple = (1, 2, 3)
print(f"{reverse_tuple(mytuple)=} (Expected (3, 2, 1))")

import math

def square_root(number):
    # Write your code here
    return math.sqrt(number)
    
def sinus(number):
    # Write your code here
    return math.sin(number)
    
def logarithm_base_10(number):
    # Write your code here
    print(math.log(number, 10))
    return math.log(number, 10)
    
# Optional tests
assert square_root(1337) == 36.565010597564445
assert sinus(1337) == -0.9683343651587963
assert logarithm_base_10(1337) == 3.1261314072619846