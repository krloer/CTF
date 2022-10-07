enc = "UFJKXQZQUNB"
key = "SOLVECRYPTO"
alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'] 

f = open("table.txt", "r")
table = f.read()
for c in table:
    if c not in alphabet:
        table = table.replace(c, "") #remove unnecessary chars
table = table[26:] #delete first line
table = list(table)
del table[::27] #delete start of each line
table = "".join(table)

inside_table = []
for i in range(0, len(table), 26):
    inside_table.append(list(table[i:i+26]))

flag = ""
for i in range(len(enc)):
    x = alphabet.index(key[i])
    c = inside_table[x].index(enc[i])
    flag += alphabet[c]

print(flag)