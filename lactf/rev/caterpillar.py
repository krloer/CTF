# import re

# with open('caterpillar.js', 'r') as file:
#     content = file.read()

# x = re.sub(r'((?:-~)+)\[\]', lambda m: str(int(len(m.group(1)) / 2)), content)

# with open('caterpillar2.js', 'w') as file:
#     file.write(x)

flag = 'lactf{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}'
# flag = [x for x in flag]
flag = list(flag)
flag[17] = chr(108)
flag[43] = chr(95)
flag[21] = chr(108)
flag[2] = chr(99)
flag[46] = chr(52)
flag[7] = chr(104)
flag[42] = chr(51)
flag[18] = chr(49)
flag[50] = chr(103) 
flag[31] = chr(108) 
flag[39] = chr(95)
flag[27] = chr(51)
flag[19] = chr(116) 
flag[4] = chr(102)
flag[25] = chr(52)
flag[11] = chr(117) 
flag[1] = chr(97)
flag[47] = chr(103) 
flag[14] = chr(114) 
flag[10] = chr(104) 
flag[36] = chr(97)
flag[54] = chr(125) 
flag[33] = chr(52)
flag[41] = chr(104) 
flag[20] = chr(116) 
flag[12] = chr(110) 
flag[3] = chr(116)
flag[13] = chr(103) 
flag[0] = chr(108)
flag[52] = chr(49)
flag[26] = chr(116) 
flag[44] = chr(102) 
flag[29] = chr(112) 
flag[38] = chr(51)
flag[8] = chr(51)
flag[35] = chr(95)
flag[53] = chr(110) 
flag[16] = chr(95)
flag[37] = chr(116) 
flag[9] = chr(95)
flag[28] = chr(114) 
flag[22] = chr(51)
flag[15] = chr(121) 
flag[32] = chr(108) 
flag[23] = chr(95)
flag[49] = chr(52)
flag[51] = chr(52)
flag[48] = chr(95)
flag[45] = chr(108) 
flag[6] = chr(116)
flag[30] = chr(49)
flag[40] = chr(116) 
flag[34] = chr(114) 
flag[24] = chr(99)
flag[5] = chr(123)

print("".join(flag))