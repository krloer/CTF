from sympy import linsolve,symbols

a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, aa, ab, ac, ad, ae, af, ag, ah, ai, aj = symbols("a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, aa, ab, ac, ad, ad, af, ag, ah, ai, aj")
system=[1441 == a*0 + b*0 + c*0 + d*0 + e*0 + f*1 + g*0 + h*0 + i*1 + j*0 + k*1 + l*1 + m*1 + n*0 + o*0 + p*0 + q*1 + r*1 + s*0 + t*1 + u*0 + v*1 + w*0 + x*1 + y*0 + z*1 + aa*1 + ab*0 + ac*0 + ad*0 + ae*1 + af*1 + ag*0 + ah*0 + ai*1 + aj*1, 2043 == a*0 + b*1 + c*0 + d*0 + e*0 + f*1 + g*1 + h*0 + i*0 + j*0 + k*1 + l*1 + m*0 + n*1 + o*0 + p*0 + q*1 + r*1 + s*1 + t*0 + u*1 + v*0 + w*1 + x*1 + y*1 + z*1 + aa*1 + ab*1 + ac*1 + ad*0 + ae*1 + af*1 + ag*1 + ah*0 + ai*1 + aj*1, 1259 == a*0 + b*1 + c*0 + d*1 + e*0 + f*1 + g*1 + h*0 + i*1 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*1 + q*0 + r*1 + s*0 + t*0 + u*1 + v*0 + w*1 + x*0 + y*1 + z*0 + aa*0 + ab*0 + ac*0 + ad*1 + ae*1 + af*1 + ag*0 + ah*1 + ai*0 + aj*0, 2031 == a*1 + b*1 + c*0 + d*1 + e*1 + f*1 + g*1 + h*1 + i*0 + j*0 + k*0 + l*1 + m*1 + n*1 + o*0 + p*1 + q*1 + r*1 + s*1 + t*0 + u*1 + v*1 + w*0 + x*1 + y*1 + z*1 + aa*1 + ab*1 + ac*0 + ad*0 + ae*0 + af*1 + ag*1 + ah*0 + ai*0 + aj*0, 1799 == a*0 + b*1 + c*0 + d*0 + e*0 + f*1 + g*0 + h*1 + i*0 + j*0 + k*1 + l*0 + m*1 + n*1 + o*1 + p*0 + q*1 + r*0 + s*1 + t*0 + u*0 + v*1 + w*1 + x*1 + y*1 + z*1 + aa*0 + ab*1 + ac*1 + ad*1 + ae*1 + af*0 + ag*1 + ah*0 + ai*0 + aj*0, 746 == a*1 + b*0 + c*0 + d*1 + e*1 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*1 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*1 + w*1 + x*0 + y*1 + z*0 + aa*0 + ab*0 + ac*1 + ad*0 + ae*0 + af*1 + ag*0 + ah*0 + ai*0 + aj*0, 55 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*1 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 1450 == a*0 + b*0 + c*1 + d*1 + e*1 + f*0 + g*0 + h*0 + i*0 + j*1 + k*1 + l*1 + m*1 + n*0 + o*0 + p*0 + q*0 + r*0 + s*1 + t*0 + u*0 + v*1 + w*0 + x*1 + y*0 + z*0 + aa*1 + ab*0 + ac*0 + ad*1 + ae*0 + af*1 + ag*1 + ah*1 + ai*1 + aj*0, 1485 == a*0 + b*0 + c*0 + d*0 + e*1 + f*1 + g*1 + h*1 + i*1 + j*0 + k*0 + l*0 + m*1 + n*0 + o*0 + p*0 + q*0 + r*0 + s*1 + t*0 + u*0 + v*0 + w*1 + x*0 + y*0 + z*1 + aa*1 + ab*1 + ac*1 + ad*1 + ae*0 + af*0 + ag*0 + ah*0 + ai*1 + aj*1, 1362 == a*0 + b*1 + c*1 + d*0 + e*0 + f*0 + g*0 + h*1 + i*0 + j*1 + k*1 + l*1 + m*1 + n*0 + o*0 + p*0 + q*1 + r*0 + s*0 + t*0 + u*0 + v*1 + w*0 + x*1 + y*1 + z*0 + aa*1 + ab*0 + ac*0 + ad*0 + ae*1 + af*0 + ag*1 + ah*1 + ai*0 + aj*0, 611 == a*0 + b*0 + c*1 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*1 + m*0 + n*1 + o*0 + p*0 + q*0 + r*1 + s*0 + t*1 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*1 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 1314 == a*1 + b*0 + c*0 + d*1 + e*1 + f*1 + g*1 + h*1 + i*0 + j*1 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*1 + t*1 + u*1 + v*0 + w*0 + x*1 + y*0 + z*0 + aa*1 + ab*0 + ac*0 + ad*0 + ae*1 + af*0 + ag*0 + ah*0 + ai*0 + aj*1, 358 == a*0 + b*0 + c*0 + d*1 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*1 + o*0 + p*0 + q*1 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*1 + aj*0, 1834 == a*1 + b*1 + c*1 + d*0 + e*0 + f*0 + g*0 + h*0 + i*1 + j*1 + k*1 + l*1 + m*0 + n*1 + o*0 + p*0 + q*1 + r*0 + s*1 + t*1 + u*0 + v*0 + w*0 + x*1 + y*1 + z*1 + aa*0 + ab*1 + ac*0 + ad*1 + ae*1 + af*1 + ag*0 + ah*1 + ai*1 + aj*0, 1500 == a*0 + b*0 + c*1 + d*1 + e*0 + f*0 + g*0 + h*1 + i*0 + j*1 + k*0 + l*1 + m*0 + n*1 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*1 + w*0 + x*1 + y*1 + z*1 + aa*1 + ab*1 + ac*1 + ad*0 + ae*1 + af*1 + ag*1 + ah*0 + ai*1 + aj*0, 1355 == a*1 + b*0 + c*0 + d*0 + e*0 + f*0 + g*1 + h*0 + i*0 + j*1 + k*1 + l*0 + m*1 + n*1 + o*0 + p*1 + q*0 + r*1 + s*0 + t*0 + u*0 + v*0 + w*0 + x*1 + y*0 + z*1 + aa*0 + ab*1 + ac*1 + ad*1 + ae*1 + af*1 + ag*0 + ah*0 + ai*0 + aj*0, 2011 == a*1 + b*1 + c*0 + d*0 + e*0 + f*1 + g*0 + h*0 + i*0 + j*0 + k*0 + l*1 + m*1 + n*1 + o*1 + p*0 + q*0 + r*1 + s*1 + t*1 + u*0 + v*0 + w*1 + x*1 + y*1 + z*1 + aa*1 + ab*0 + ac*1 + ad*1 + ae*0 + af*1 + ag*1 + ah*0 + ai*1 + aj*1, 1990 == a*0 + b*1 + c*0 + d*0 + e*0 + f*1 + g*0 + h*1 + i*1 + j*0 + k*0 + l*1 + m*0 + n*1 + o*1 + p*1 + q*1 + r*1 + s*1 + t*1 + u*0 + v*0 + w*1 + x*1 + y*1 + z*0 + aa*1 + ab*1 + ac*1 + ad*1 + ae*0 + af*1 + ag*0 + ah*0 + ai*1 + aj*0, 1939 == a*1 + b*1 + c*0 + d*1 + e*0 + f*0 + g*1 + h*1 + i*0 + j*1 + k*1 + l*0 + m*0 + n*1 + o*1 + p*1 + q*1 + r*1 + s*0 + t*1 + u*0 + v*1 + w*1 + x*0 + y*0 + z*0 + aa*1 + ab*1 + ac*0 + ad*1 + ae*0 + af*0 + ag*1 + ah*1 + ai*0 + aj*1, 1990 == a*1 + b*0 + c*0 + d*0 + e*1 + f*1 + g*1 + h*0 + i*1 + j*0 + k*0 + l*1 + m*0 + n*1 + o*1 + p*1 + q*1 + r*1 + s*1 + t*0 + u*1 + v*0 + w*1 + x*1 + y*0 + z*0 + aa*1 + ab*0 + ac*1 + ad*0 + ae*1 + af*1 + ag*1 + ah*0 + ai*1 + aj*1, 278 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*1 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*1 + u*0 + v*0 + w*0 + x*0 + y*0 + z*1 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 1859 == a*1 + b*0 + c*1 + d*1 + e*0 + f*0 + g*1 + h*0 + i*1 + j*1 + k*1 + l*1 + m*1 + n*1 + o*1 + p*1 + q*1 + r*0 + s*1 + t*0 + u*1 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*1 + ad*1 + ae*0 + af*0 + ag*1 + ah*0 + ai*0 + aj*1, 2111 == a*0 + b*1 + c*1 + d*1 + e*1 + f*1 + g*1 + h*1 + i*1 + j*1 + k*0 + l*1 + m*1 + n*1 + o*0 + p*1 + q*1 + r*1 + s*1 + t*1 + u*1 + v*0 + w*1 + x*0 + y*1 + z*0 + aa*0 + ab*1 + ac*0 + ad*0 + ae*0 + af*1 + ag*0 + ah*0 + ai*0 + aj*0, 1510 == a*0 + b*0 + c*1 + d*0 + e*0 + f*0 + g*1 + h*0 + i*1 + j*1 + k*0 + l*0 + m*0 + n*0 + o*0 + p*1 + q*1 + r*1 + s*1 + t*1 + u*1 + v*0 + w*1 + x*1 + y*0 + z*0 + aa*1 + ab*1 + ac*1 + ad*1 + ae*0 + af*1 + ag*0 + ah*0 + ai*0 + aj*0, 888 == a*0 + b*0 + c*1 + d*0 + e*0 + f*0 + g*0 + h*1 + i*0 + j*1 + k*0 + l*0 + m*1 + n*0 + o*0 + p*0 + q*1 + r*0 + s*0 + t*0 + u*1 + v*0 + w*0 + x*0 + y*1 + z*1 + aa*1 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*1 + ai*0 + aj*0, 1224 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*1 + j*1 + k*1 + l*1 + m*0 + n*0 + o*1 + p*1 + q*0 + r*1 + s*1 + t*1 + u*0 + v*0 + w*0 + x*0 + y*0 + z*1 + aa*0 + ab*0 + ac*1 + ad*1 + ae*0 + af*1 + ag*0 + ah*0 + ai*0 + aj*0, 68 == a*1 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 85 == a*0 + b*1 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 67 == a*0 + b*0 + c*1 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 84 == a*0 + b*0 + c*0 + d*1 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 70 == a*0 + b*0 + c*0 + d*0 + e*1 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 123 == a*0 + b*0 + c*0 + d*0 + e*0 + f*1 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 125 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*1, 76 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*1 + h*0 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 105 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*1 + i*0 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0, 110 == a*0 + b*0 + c*0 + d*0 + e*0 + f*0 + g*0 + h*0 + i*1 + j*0 + k*0 + l*0 + m*0 + n*0 + o*0 + p*0 + q*0 + r*0 + s*0 + t*0 + u*0 + v*0 + w*0 + x*0 + y*0 + z*0 + aa*0 + ab*0 + ac*0 + ad*0 + ae*0 + af*0 + ag*0 + ah*0 + ai*0 + aj*0]
print(linsolve(system, [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, aa, ab, ac, ad, ae, af, ag, ah, ai, aj]))