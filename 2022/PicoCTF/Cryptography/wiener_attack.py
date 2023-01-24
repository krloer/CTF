from Crypto.Util.number import *
from sympy import solve, Symbol

c = 26819268161155260619804910428982034729537023230276102286533915160041083011124704097015457691605205132320262758079895175928088515337342360493619313196826344090567523771066279864608520097863384900323246818802767068756002644318500590992224613324895653223180681078069461201441728120215115060876693514846684962046
n = 97042078511388648147008773899693379546806663972819898537796770259486369747674304403685781555289616287437896481223179441633039504189084968035146150938826914046506708814540389818848865650719230934445034872018517948009653993125136692540823146330280086221140457234870211155142191981929955123151108108227628705061
e = 35946221161095034928195804653728671780388320842714430601987075606208655748848353596019798292855053140363126459613365339862427798449976462136534503296064646722090428285215958863461344280686243969159344981997696819284841222740532296561034719627540188107518221810592751651882745434334920681763595734283297081379

"""
c, n and e are known
e*d - k*phi = 1 
e/phi - k/d = ca. 0 (1/d*phi) (phi ca lik N)
e/N ca. lik k/d ___ find match -> possible correct d

Simplication:
phi is in general even, d has to be odd because (ed kongruent med 1 mod phi)
phi has to be a whole number, (phi = ed-1/k)

phi = N - (p+q) + 1
p + q = N - phi + 1

(x1-p)(x2-p) = 0
x²-(p+q)+pq = 0
x²-(N-phi+1)x+N = 0
Solutions to this have to be whole numbers and factors of N
"""

def get_expansions(e, n):
    exp = []
    a = e // n
    b = e % n
    exp.append(a)

    while (b > 0):
        e = n
        n = b
        a = e // n
        b = e % n
        exp.append(a)
    
    return exp

def get_convergents(exp):
    n = []
    d = []

    for i in range(len(exp)):
        if i == 0:
            n.append(exp[i])
            d.append(1)
        elif i == 1:
            n.append(exp[i]*exp[i-1]+1)
            d.append(exp[i])
        else:
            n.append(exp[i]*n[i-1]+n[i-2])
            d.append(exp[i]*d[i-1]+d[i-2])
    return n, d


def get_private_exponent(k, d):
    for i in range(len(k)):
        if k[i] == 0 or d[i] % 2 == 0:
            continue
        
        phi = (e * d[i] - 1)//k[i]

        if (type(phi) != int):
            continue

        x = Symbol('x', integer=True)
        r = solve(x**2 - (n-phi+1)*x + n, x)
        if(len(r) == 2):
            p = r[0]
            q = r[1]
            if (p*q == n):
                return d[i]


exp = get_expansions(e, n)
k, d = get_convergents(exp)
d = get_private_exponent(k,d)

m = pow(c,d,n)
flag = long_to_bytes(m)
print(m)
print(flag)