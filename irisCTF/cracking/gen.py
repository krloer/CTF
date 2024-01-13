words = ["tiramisu", "portofino", "swans", "swan", "mimosa", "mimosas", "mom", "mother", "brunch", "milan", "italy", "winter", "netherland", "netherlands", "berlin", "sunrise", "amsterdam", "europe", "photography", "travel", "experience", "april", "orange", "juice", "happy", "hour", "manhattan"]
wordlist = []

def add(cap, suffix):
    for a in range(len(words)):
        for b in range(len(words)):
            for c in range(len(words)):
                if a != b and b != c and a != c:
                    first = words[a].capitalize() if cap[0] else words[a]
                    second = words[b].capitalize() if cap[1] else words[b]
                    third = words[c].capitalize() if cap[2] else words[c]
                    wordlist.append(first+second+third+suffix+"\n")


for suf in ["08041965", "04081965", "19650408", "27041996", "04271996", "19962704", "0804196527041996", "2704199608041965", "0408196504271996", "0427199604081965", "1965040819962704", "1996270419650408", "0804", "0408", "2704", "0427", "0490", "0465", "0865", "08042704", "04080427", "27040804", "04270408"]:
    add([0,0,0], suf)
    add([0,0,1], suf)
    add([0,1,0], suf)
    add([1,0,0], suf)
    add([0,1,1], suf)
    add([1,1,0], suf)
    add([1,0,1], suf)
    add([1,1,1], suf)
    for c in words:
        wordlist.append("Ilove" + c.capitalize() + suf + "\n")
        wordlist.append("Ilove" + c + suf + "\n")
        wordlist.append("ILove" + c.capitalize() + suf + "\n")
        wordlist.append("ILove" + c + suf + "\n")
        wordlist.append(c + "isgreat" + suf + "\n")
        wordlist.append(c.capitalize() + "isgreat" + suf + "\n")
        wordlist.append(c + "IsGreat" + suf + "\n")
        wordlist.append(c.capitalize() + "IsGreat" + suf + "\n")

with open("wordlist.txt", "w") as f:
    f.writelines(wordlist)