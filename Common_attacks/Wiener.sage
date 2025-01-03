#!/usr/bin/env python
# coding: utf-8

# In[66]:


p = random_prime(2**1024)
q = random_prime(2**1024)

n = p * q

phi = (p - 1)*(q - 1)

bound = 2 ** (n.bit_length() // 4)



# generating d to be a prime, so that it is guaranteed that there's an inverse
# any coprime to phi can be used
# in any case, this doesn't affect numberical results

d = random_prime(int(1/3 * bound)) 

print(d)


e = pow(d, -1, phi)


print(f'{e=}')
print(f'{n=}')


# Because $k < d < 1/3*N^{1/4}$
# 
# $ \big| \dfrac{e}{N} - \dfrac{k}{d} \big| <= \dfrac{1}{dN^{1/4}} < \dfrac{1}{2d^2} $
# 
# Note, $d$ is the private exponent, and $k$ is derived from the relation $ ed = 1 + kφ(N) $
# 
# 
# As stated in the paper, all fractions of this form are obtained as convergents of the continued fraction expansion of $ \dfrac{e}{N} $
# 
# https://math.stackexchange.com/a/2698953    
# https://en.wikipedia.org/wiki/Wiener%27s_attack#Example

# In[69]:


def continued_fraq(num, denom):
    decomp = []
    
    while num > 1:
        decomp.append(num // denom)
        
        num, denom = denom, num % denom
        
    return decomp
              

e1 = 17993 #test vars from wikipedia
n1 = 90581
    
    
decomp = continued_fraq(e, n)
print(decomp)



# In[70]:


from math import gcd

def calc_fraq(decomp):
    
    if len(decomp) == 1:
        return decomp[0]
    
    decomp = decomp[::-1]
    
    nom, denom = decomp[0], 1
    
    for idx in range(len(decomp) - 1):
        #reverse 
        nom, denom = denom, nom
        
        #add nxt
        nom = nom + decomp[idx + 1] * denom
        
    
    return (nom, denom)
    


def calc_convergents(decomp):
    convergents = []
    

    #building all i-th fractions separately
    #runs in O(n^2), where n is log2(N), still negligible complexity.
    for i in range(len(decomp)):
        convergents.append(calc_fraq(decomp[:i + 1]))
    

    return convergents



# decomp = continued_fraq(e, n)

convergents = calc_convergents(decomp)
        
print(convergents)


# 
# Having the continued fractions expansion of $ \dfrac{e}{N} $, we can recover p and q: 
# 
# $ φ(N) = \dfrac{ed - 1}{k} $
# 
# But since p, q primes, we can solve the following system
# 
# $\begin{cases}
# φ(N) = (p - 1)(q - 1) = N - p - q + 1\\
# N = pq
# \end{cases}$
# 
# 

# In[71]:


#we can use sage to solve this as a 2nd degree equation equation
#ToDo: develop a proof-of-concept that doesn't use sage, but rather Fact 1 from page 3 of 20 years of RSA
p = q = -1

for k, d in convergents[1:]:
    phi = (e*d - 1) // k
    R.<x> = PolynomialRing(ZZ)
    Eq = x^2 - (n - phi + 1)*x + n
    
    primes = Eq.roots()
    if not primes:
        continue
    print('[+]Found factorisation of n')
    p, q = [i[0] for i in primes]
    assert p * q == n

phi = (p - 1)*(q - 1)
d = pow(e, -1, phi)

print(f'{p = }\n{q = }\n{phi = }\n{d = }')
    
    

