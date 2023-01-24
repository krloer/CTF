enc = "DL\Ltw?}Pl};ldj}Pbn|{<}r"
dec = ""

for c in enc:
    a = ord(c) ^ 0xf
    dec += chr(a)

print(dec)
