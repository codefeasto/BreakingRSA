def bytes_to_long(b):
    return int(b.hex(), base=16)

def long_to_bytes(l):
    return bytes.fromhex(hex(l)[2:])


phi = 3
e = 3

#assure coprime to e
while phi % e == 0:
    p = random_prime(2**1024)
    q = random_prime(2**1024)

    n = p * q

    phi = (p - 1)*(q - 1)

e = 3

d = pow(e, -1, phi)

m = bytes_to_long(b"Well hidden message!!!! Lorem ipsum \
   dolor sit amet, consectetur adipiscing elit, \
   sed do eiusmod tempor incididunt ut labore ")

print(m.bit_length())

c = pow(m, e, n)


R.<x> = PolynomialRing(Integers(n))

known = (m >> (m.bit_length() // 3)) * 2 ^ (m.bit_length() // 3)

f_x = (known + x) ^ 3 - c

a = f_x.coefficients()


X = round(n ^ (1/3))


B = matrix(ZZ, [
    [n,         0,        0,   0],
    [0,     n * X,        0,   0],
    [0,         0,  n * X^2,   0],
    [a[0], a[1]*X, a[2]*X^2, X^3]
])


B = B.LLL()

coefs = B.rows()[0]
ff_x = sum([coefs[i]*x^i//(X**i) for i in range(len(coefs))])
print(ff_x)
print(ff_x.roots(multiplicities=False))



