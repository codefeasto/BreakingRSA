from pwn import *
from Crypto.Util.number import *
from sympy import sieve
from sage.all import carmichael_lambda, factor, is_prime, is_prime_power, euler_phi
from itertools import chain, combinations, product
from math import prod
from tqdm import trange
from gmpy2 import mpz
from random import randint, choices



def powerset(iterable):
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(1, len(s)+1))


# precalculate N of appropriate bit length and as small Carmichael's lambda as possible
target_bitlength = 2024
small_primes = list(sieve[1:7]) + [17]
uses = [6, 4, 2, 2, 2, 2, 2]
assert len(small_primes) == len(uses)
prime_uses = {s: u for s, u in zip(small_primes, uses)}

print(small_primes)
diff_primes = set()
cnt = 0
all_subsets = powerset(small_primes)
for subset in all_subsets:
    for up in product(*[list(range(i)) for i in [prime_uses[p] for p in subset]]):
        potp = prod([subset[i]**up[i] for i in range(len(subset))]) + 1
        if is_prime(potp):
            if potp not in diff_primes:
                diff_primes.add(potp)

diff_primes = list(diff_primes)
diff_primes = sorted(diff_primes, key = lambda num: num.bit_length())
s = 124
mul = 1
for np in diff_primes[::-1]:
    mul *= np
    if mul.bit_length() > target_bitlength:
        mul //= np
        break

small_primes = diff_primes[:40]
while True:
    tN = mul * prod(choices(small_primes, k= randint(1, 10)))
    if tN.bit_length() == target_bitlength:
        break


cl = carmichael_lambda(tN)
print(factor(cl))
print(f"{cl = }")
print(f"{cl.bit_length()}")

while True:
    conn = process(["python", "server.py"])
    conn.sendlineafter(b"= ", str(tN).encode())
    c = int(conn.recvline().decode().strip().split()[-1])
    conn.close()

    c, n = mpz(c), mpz(tN)
    c0 = c
    for d in trange(cl):
        c = c*c0 % n
        flag = long_to_bytes(c)
        if flag.startswith(b"ictf{"):
            print(flag)
            exit()

