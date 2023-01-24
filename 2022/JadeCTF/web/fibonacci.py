import requests

#figured out fibonacci page numbers return constant values and form a string

numbers = [1,2]

def fib():
    for i in range(1, 75):
        numbers.append(numbers[i-1]+numbers[i])

fib()

print(numbers)

flag = ""
url = "http://34.76.206.46:10008/?page="

for num in numbers:
    r = requests.get(url + str(num))
    flag += r.text

print(flag)