supersecret = [16, 41, 85, 127, 238, 147, 98, 228, 78, 100, 2, 26,112, 125, 214, 152, 96, 224, 73, 109, 51, 56]
key = [118, 69, 52, 24, 149, 247, 45, 144, 0, 1]


array = supersecret
array2 = supersecret

for i in range(len(array)):
	# byte b = array[i];
	array2[i] = (array[i] ^ key[i % len(key)])

flag = "".join([chr(x) for x in array2])
print(flag)
