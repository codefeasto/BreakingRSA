from pwn import *
from gmpy2 import mpz

def attempt():
    #conn = remote('krsa.ctf.intigriti.io', 1346)
    conn = process(["python", "server.py"])
    conn.recvline()
    n = mpz(int(conn.recvline().decode().split("=")[-1]))
    e = mpz(int(conn.recvline().decode().split("=")[-1]))
    conn.recvline()
    c = mpz(int(conn.recvline().decode().split("=")[-1]))
    conn.recvuntil(b"? ")

    forward = {}
    backward = {}

    for k in range(2**15, 2**16):
        f = pow(k, e, n)
        forward[f] = k
        b = c * pow(f, -1, n) % n
        backward[b] = k
    intersect = list(set(forward.keys()).intersection(set(backward.keys())))
    if intersect == []:
        conn.close()
        return
    print(intersect)
    k = intersect[0]
    m = forward[k]*backward[k]
    print(m, m.bit_length())
    conn.sendline(str(m).encode())
    print(conn.recvline())
    exit()


while True:
    attempt()
