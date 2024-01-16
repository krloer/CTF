m = 235322474717419
F = GF(m)
C = EllipticCurve(F, [0, 8856682])

# Given public parameters
public_base = C((185328074730054, 87402695517612, 1))
Q1 = C((184640716867876, 45877854358580, 1))
Q2 = C((157967230203538, 128158547239620, 1))

# Calculate shared secret
secret = Q1.discrete_log(public_base)

# Demonstrate finding my_private_key using the shared secret
my_private_key = Q2.discrete_log(public_base)

# Validate
assert(my_private_key * public_base == Q2)
assert(secret * public_base == Q1)

print(secret)
print(my_private_key)