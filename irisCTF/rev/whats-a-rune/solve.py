with open("the", "rb") as file:
    enc = file.read().decode("utf-8")

enc_nums = [ord(c) for c in enc]
dec_nums = [enc_nums[0]]

for i in range(1, len(enc_nums)): 
    dec_nums.append(enc_nums[i]-dec_nums[i-1])

print("".join([chr(n) for n in dec_nums]))