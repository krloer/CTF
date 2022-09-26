# flag="f"

# encrypted_str = ''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

# print(encrypted_str)

encoded_str="灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弰㑣〷㘰摽"
decoded_str=""

for i in range (len(encoded_str)):
    decoded_str += chr((ord(encoded_str[i]) >> 8))
    decoded_str += chr((ord(encoded_str[i]))-((ord(encoded_str[i])>>8)<<8))

print(decoded_str)



