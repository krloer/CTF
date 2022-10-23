from decimal import getcontext, Decimal
from Crypto.Util.number import long_to_bytes

#found n and e with openssl rsa -pubin -inform PEM -text -noout < key.pem
c = int("125eade3ceb41b6cf53f5edb012024e2049568540d0b833323bed4946d66487e1f03439592e5bf12430a44be9b8f84fb00f33e62b2e85d5b20e74c276d75cf443a06e2ca37e9907445d9dc03a3f35056b87f0a8eccd2f83f1eccab055c919065",16)
e = 3
n = int("009c8630a8b1c85adb58453b8a2ffddfa6b26dc6ca34e1f5b562787ae83e3cd427b30102b4b5d7a1ddf377385d5cf292405295ba304285b3b91b5a565052c2be3e1a1c3f68292804a075996e1990a8bc60ee39605477ed3d5f61761b8b73efd3e7fe48113a1086bdc9fc55e7c6f721a902e58e989ca20577efbbc188823fb7bb26b6a188a27b6600b172a86bd002a1d5ca6e37f97718c0c0273546408a3131187be6270c2b987fe188309ae5b59dea66249b7ab0763aec8ec0b1c045ec7792cd34aba2d3d772187b4e627e599030df48c5e8e4e5c3b85f1307ab0b6a3988f88e0a3fa72f6a7e09113e9d7b7425cff8e6bb55d19eeec87bb0a571d8ffda9cd14fc3ef37be9a1ec468baeacf06782075db0e4a58a24b5e2e9293ab10f826598ad2abb0d00bc02b1a9a1a53eba1139df6a9b439ba5555f7dca08e2b136469dfaa763e7caff1b39011c8243e05b138c7705e06961297b3ac4f79a2629a805b535ecc27c7773f04d77ba89dd8a0d0faec14037a9928e4e9c38bf9d3c4b3160e2f931fdb6c4c2660b419cdeab55d554f3818b6f70ba20e7e1bb5ed1f9cf056c0c6b660b91c3ce203f6e5c4030146687c02a6d11db268976d59a3de788ca49ba0e2eafb4aff805e3bd3fcda2e7c475eecfdcf63f4c1f764e3ba06aa9ef0af2a57f0e0bee7f3d8704c3ec5e29c98d05bad5a518b5caa16e62e401c7e475514cb9e7519e053", 16)

"""
Since n is so much larger than c and e, and c is similar size to m, its possible that m^e mod n = m^e
m = c^d mod n 
d = inverse(e, phi) - but since phi is similar to n this just equals inverse(e) which is 1/e
m = c^1/e mod n - and n was to large to be relevant
so m = c^1/e
"""

e = Decimal(e)
c = Decimal(c)

getcontext().prec = 1000
m = pow(c, 1/e)
m = round(m)

m = hex(m)[2:]
m = long_to_bytes(int(m, 16))
print(m)
