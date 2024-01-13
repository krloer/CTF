from Crypto.Util.number import long_to_bytes
# from config import e, n as d, x, y, c as ct
import gmpy2

e = 65537
d = 12619841721660584319738721492771644798997241534987459553234688004105984888705
c = 50234119019135912961379502124791010762883761532837431066341152416555395726699

kn = e * d - 1
count = 0


def solve(a, b, c):
    D = b ** 2 - 4 * a * c
    assert gmpy2.is_square(D)
    x1 = (-b + gmpy2.isqrt(D)) // (2 * a)
    x2 = (-b - gmpy2.isqrt(D)) // (2 * a)
    return x1, x2


for k in range(3, e):
    if kn % k == 0:
        count += 1
        phi_n = kn // k
        # coefficients of quadratic eq
        a = x - 1
        b = x * y - 1 + (x - 1) * (y - 1) - phi_n
        c = (y - 1) * (x * y - 1)
        try:
            k1, k2 = solve(a, b, c)
            if (x * y - 1) % k1 == 0:
                k2 = (x * y - 1) // k1
            elif (x * y - 1) % k2 == 0:
                k1, k2 = k2, (x * y - 1) // k2
            else:
                assert False
            p, q = x + k2, y + k1
            N = p * q

            flag = long_to_bytes(pow(ct, d, N)).strip()
            break
        except AssertionError:
            pass

print(flag)
