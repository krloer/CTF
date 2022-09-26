from re import A
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))  #01100001
		enc += ALPHABET[int(binary[:4], 2)] #00010110 = 6 = g
		enc += ALPHABET[int(binary[4:], 2)] #01100001 = 1 = b
	return enc

# print(b16_encode("z")) #  abcdefghijklmnop  => g + shift en til høyre (p => a)
#LOWERCASE OFFSET = a:97, b:98, p:112

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET #0 til 15 
	t2 = ord(k) - LOWERCASE_OFFSET #0 til 15
	return ALPHABET[(t1 + t2) % len(ALPHABET)] # 0-30  % 16

flag = "redacted" 
key = "a"
assert all([k in ALPHABET for k in key])
assert len(key) == 1


b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
	enc += shift(c, key[i % len(key)]) #r:(0, )
print(enc)



# print(b16_decode("mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj"))
# print(b16_decode("mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj"))

for i in enc:
    for k in range(len(ALPHABET)):
        index = ALPHABET.index(i)
        if(k <= index):
            b16[k]+=chr(index -k+97)
        else:
            b16[k]+=chr(index +16-k+97)
print(enc)

def b16_decode (ting):
	dec = ""
	for i in range(0, len(ting), 2):
		if (i < len(ting)):
			exp = ting[i]+ting[i+1]
		else:
			break
		if (ting[i] == "h"):
			ALPHABET = "qrstuvwxyz"
		else:
			ALPHABET = "abcdefghijklmnop"
	
		binary = "{0:08b}".format(ord(exp[0])-2)[4:]  #0111 7
		binary += "{0:08b}".format(ord(exp[1])-2)[4:]  #0010 2
		dec += ALPHABET[int(binary[4:], 2)]
	return dec

print(b16_decode(enc))





























