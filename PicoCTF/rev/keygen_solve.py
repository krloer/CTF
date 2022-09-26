import hashlib

key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
bUsername_trial = b"PRITCHARD" 
username_trial = bUsername_trial
dynamic_flag = [0,0,0,0,0,0,0,0]
order = [6, 4, 2, 0, 1, 3, 5, 7]


for i in range(len(order)):
    dynamic_flag[order[i]] = hashlib.sha256(username_trial).hexdigest()[i+1]

result = "".join(dynamic_flag)
print(key_part_static1_trial + result + key_part_static2_trial)
