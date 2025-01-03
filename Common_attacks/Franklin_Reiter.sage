from copy import copy

def bytes_to_long(b):
    return int(b.hex(), base=16)

def long_to_bytes(l):
    return bytes.fromhex(hex(l)[2:])

# p = random_prime(2^1024)
# q = random_prime(2^1024)
p = 97795105686558181161179482316061945459915127735146850780792541107490161069956561938949103547607412104207767590789953118939171819052808031190586057898723379045709525304902529198990453813014547153232339765072650093324400479141014456703016936300318426554771715246905600808221936183783854688711162471497059196589
q = 100394917007611677578525145051033297655568285438149360162834583434632936892945288551178102540164376570353936449800092519701311381667670020257183461616315488576793944610497205303644478208342950053542340538535300585171249684336698718909510901557362549354714136811204804667024117511645775227083399901243792036759


n = p * q

# 
e = 3

a = randint(0,2^16)
b = randint(0,2^16)

m_2 =  bytes_to_long(b"Well hidden message!!!! Lorem ipsum \
   dolor sit amet, consectetur adipiscing elit, \
   sed do eiusmod tempor incididunt ut labore ")

# m_2 = bytes_to_long(b"Well hidden message!!!!!")

m_1 = (a * m_2 + b) % n

c_2 = pow(m_2, e, n)
c_1 = pow(m_1, e, n)
global g
g = 0


def polyDivZn(x1, x2): 
    global g
    assert x2 != 0
    q = 0
    r, d = x1, x2
    print(r.poly, d.poly)
    
    while r.poly != 0 and d.poly != 0 and r.degr() >= d.degr():
        print(d.lead())
        print(type(d.lead()))
        d_i = d.lead().inverse()
        print(d_i)
        
#         print(r.poly, r.lead(), d.lead())
        t = (r.lead()* d_i) % n
        print(t)     
        
        
        q += t * xs ^ (r.degr() - d.degr())
        r.poly -= t * d.poly * xs ^ (r.degr() - d.degr())
        # r.poly = r.poly.simplify_full()
        print(r.poly)
        
    
       

#     print('polyDiv ', q, r)
    
    g += 1
    
    return PolyZn(q), r

def polyGCDZn(x1, x2):
    if x2.poly == 0:   
        return PolyZn(x1.poly * x1.lead().inverse())
    
    x1, x2 = x2, x1 % x2
    # print('polyGCD: ', x1, x2)
    
    
    return polyGCDZn(copy(x1), copy(x2))
    


class PolyZn:
    def __init__(self, poly):
        self.poly = poly
    
    def __repr__(self):
        return str(self.poly)
    
    def __eq__(self, other):
        if type(other) == type(self):
            return self.poly == other.poly
        else:
            return self.poly == other
        
    def __mod__(self, other):
        return polyDivZn(self, other)[1]
    
    def degr(self):
        return self.poly.degree()
    
    def lead(self):
        #print(self.poly.coefficient(xs, n=self.degr()), self.degr())
        return self.poly.coefficients()[-1]

    
# xs = var('xs')

R.<xs> = PolynomialRing(Integers(n))


xx = PolyZn(xs ^ 3 + xs^2 + xs + 1)
xw = PolyZn(xs ^ 2 - 1)

res1 = polyGCDZn(copy(xx), copy(xw))

assert res1 == xs + 1



P1 = (a*xs + b) ^ e - c_1
P2 = xs ^ e - c_2

P1 = PolyZn(P1)
P2 = PolyZn(P2)

print(P1, P2)

out = polyGCDZn(P1,P2)


msg = out.poly.coefficients()[0]


print(long_to_bytes(-msg))
