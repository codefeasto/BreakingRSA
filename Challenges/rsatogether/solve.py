from sage.all import *
from pwn import *
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from tqdm import tqdm
from gmpy2 import mpz, gcd

def get_num(conn):
    return int(conn.recvline().decode().strip().split()[-1])

def get_flag(conn):
    conn.sendlineafter(b"> ", b"3")
    conn.recvline()
    enc = get_num(conn)
    return enc

def decrypt_from_d(conn, d, enc= None):
    if enc == None:
        enc = get_flag(conn)
    pt = long_to_bytes(pow(enc, d, n))
    if b"ECSC" in pt:
        print(pt)
    return enc, pt

def reshare(conn, num):
    conn.sendlineafter(b"> ", b"2")
    conn.sendlineafter(b"? ", str(num).encode())
    share = get_num(conn)
    return share

def gcd_list(llist):
    if len(llist) == 2:
        return gcd(llist[0], llist[1])
    return gcd_list([gcd(llist[0], llist[1])] + llist[2:])

conn = process(["sage", "rsatogether.sage"])
#conn = remote("rsatogether.challs.jeopardy.ecsc2024.it", 47001)
n = get_num(conn)
e = get_num(conn)

conn.sendlineafter(b"? ", b"2")
get_num(conn)

FF = QQ
size = 100
M1 = matrix(FF, size, size)
M2 = matrix(FF, size, size)
v1 = vector(FF, size)
v2 = vector(FF, size)

for i in tqdm(range(size+1)):
    nshares = i + 2
    M = matrix(ZZ, [[x**i for i in range(nshares)] for x in range(1, nshares+1)])
    coeffs = M.solve_left(vector(ZZ, [1] + [0]*(nshares - 1)))
    coeffs = [int(ii) for ii in coeffs]
    mycoeff = coeffs[-2]

    polyy = [1]*size
    polyy = polyy[:nshares]
    polyy += [0]*(size - len(polyy))
    
    my_x = nshares - 1
    share = reshare(conn, my_x)
    if i < size-1:
        v1[i] = share
        v2[i] = share
    elif i == size-1:
        assert v1[-1] == 0
        v1[-1] = share
    elif i == size:
        assert v2[-1] == 0
        v2[-1] = share
    coeff = nshares * (-1)**nshares
    assert coeff == mycoeff
    
    if i < size-1:
        for j in range(size):
            M1[i, j] = polyy[j]*coeff*(my_x**j)
            M2[i, j] = polyy[j]*coeff*(my_x**j)
    elif i == size-1:
        for j in range(size):
            assert all(ii == 1 for ii in polyy)
           
            M1[-1, j] = polyy[j]*coeff*(my_x**j)
    elif i == size:
        for j in range(size):
            M2[-1, j] = polyy[j]*coeff*(my_x**j)

enc = get_flag(conn)

print("[+] Solving ... this will take some time ...")
R1 = (M1.augment(v1)).rref().column(-1)
R2 = (M2.augment(v2)).rref().column(-1)
RD = R1 - R2
common_denom = prod([rd.denominator() for rd in RD])
RDD = common_denom*RD
maybe_phi = gcd_list([int(ii) for ii in RDD])
my_d = pow(e, -1, maybe_phi)
decrypt_from_d(conn, my_d, enc)



