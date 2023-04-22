enc = "heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V091B0AE}2 "
flag = ""

for i in range(0,len(enc),3):
    try:
        flag += enc[i+2] + enc[i] + enc[i+1]
    except:
        break

print(flag)
