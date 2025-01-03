from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


###### NIST P256 
p256 = 2^256-2^224+2^192+2^96-1
a256 = p256 - 3
b256 = 41058363725152142129326129780047268409114441015993725554835256314039467401291
## Curve order
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
FF = GF(p256)
EC = EllipticCurve([FF(a256), FF(b256)])
EC.set_order(n)

N = 2532601576517180151973272804472458662188911309902804927674973120731632668465722549385259120121020332032083313975900081376517867702500494081504179013647029
e = 65537
S = EC(64249798141205617809160223067814527035042879912280536230689430488390850022518, 45923098905078689255634808917746174708164700128176753039048172835317590674783)
ciphertext = b'\x12\xed\xb1r\xb0L]\xcff\x9b\xb1o\x88\xd3\xc9\xac~P{\x0e\x1e\x12:\x8e\xae<\xeb\xc8\x11\xc5\x94\xbfs\x9es,\xb5\xc6f\xcc\xbf\xc8\xb7\xe3\xa0\x1e;XhO A`\x92\x9f\xa1\xbbZ^\xe5\xf8\xc2@t'

Sx, Sy = S.xy()
# n = p*q
# Sx = l^2 - p - q
# Sy = l*(p - Sx) - Y(p)

a = a256
b = b256

P.<xp, xq, yp, yq> = PolynomialRing(FF)
p1 = yp^2 - (xp^3 + a*xp + b)
p2 = yq^2 - (xq^3 + a*xq + b)

pol1 = (yq - yp)^2 - xp*(xq - xp)^2 - xq*(xq - xp)^2 - Sx*(xq - xp)^2
pol2 = (yq - yp)*(xp - Sx) - yp*(xq - xp) - Sy*(xq - xp)
pol3 = N - xp*xq

I = P * (p1, p2, pol1, pol2, pol3)
V = I.groebner_basis()
# print monomials of the polynomials in the groebner basis to inspect them manually and select appropriate ones to use resultant on
print(*[Vi.monomials() for Vi in V], sep= '\n')
print(len(V))


V1, V2, V3, V4 = V[:4]

def resultant(p1, p2, var):
    p1 = p1.change_ring(QQ)
    p2 = p2.change_ring(QQ)
    var = var.change_ring(QQ)
    r = p1.resultant(p2, var)
    return r.change_ring(FF)


# Get rid of variables
h12 = resultant(V1, V2, xp) 
h34 = resultant(V3, V4, xp) 
h1234 = resultant(h12, h34, yp)
print(h1234.variables())

# this polynomial only has one variable, so finding roots is trivial
unipol = resultant(h1234, p2, yq).univariate_polynomial()

poss_xq = unipol.roots(multiplicities= False)
print(poss_xq)
for r in poss_xq:
    if N % int(r) == 0:
        print("success")
        p = int(r)
        e = 65537
        q = N//p
        print(f"{p = }")
        print(f"{q = }")
        assert is_prime(p), is_prime(q)
        assert p*q == N
        phi = (p - 1) * (q - 1)

        d = int(pow(e, -1, phi))

        key = RSA.construct((int(N), int(e), int(d)))
        cipher = PKCS1_OAEP.new(key)
        ciphertext = b'\x12\xed\xb1r\xb0L]\xcff\x9b\xb1o\x88\xd3\xc9\xac~P{\x0e\x1e\x12:\x8e\xae<\xeb\xc8\x11\xc5\x94\xbfs\x9es,\xb5\xc6f\xcc\xbf\xc8\xb7\xe3\xa0\x1e;XhO A`\x92\x9f\xa1\xbbZ^\xe5\xf8\xc2@t'

        message = cipher.decrypt(ciphertext)
        print(message)
        exit()



