import random

enc = "bDacadn3af1b79cfCma8bse3F7msFdT_}11m8cicf_fdnbssUc{UarF_d3m6T813Usca?tf_FfC3tebbrrffca}Cd18ir1ciDF96n9_7s7F1cb8a07btD7d6s07a3608besfb7tmCa6sasdnnT11ssbsc0id3dsasTs?1m_bef_enU_91_1ta_417r1n8f1e7479ce}9}n8cFtF4__3sef0amUa1cmiec{b8nn9n}dndsef0?1b88c1993014t10aTmrcDn_sesc{a7scdadCm09T_0t7md61bDn8asan1rnam}sU"

init = [n for n in range(61)]

for i in range(1337):
    random.seed(i)
    flag = ["" for _ in range(61)]

    pos_mapping = random.choices(init, k=len(init)*5)

    for j,c in enumerate(enc):
        flag[pos_mapping[j]] = c

    flag = "".join(flag)

    if "DUCTF{" in flag:
        print(flag)

