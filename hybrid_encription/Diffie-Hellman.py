from random import randint
from sympy import *


def prim_roots(num):
    o = 1
    roots_ls = []
    r = 2
    while r < num:
        k = pow(r, o, num)
        while k > 1:
            o = o + 1
            k = (k * r) % num
        if o == (num - 1):
            roots_ls.append(r)
        o = 1
        r = r + 1
    return roots_ls


if __name__ == '__main__':
    # Both the persons will be agreed upon the
    # public keys G and P
    # A prime number P
    P = randprime(1000, 10000)

    # A primitive root for P: G
    roots = prim_roots(P)
    G = roots[randint(0, len(roots) - 1)]

    print(f'The value of P is: {P}')
    print(f'The value of G is: {G}')

    # Alice will choose the private key a
    a = randint(5, 25)
    print(f'The private key a for Alice is: {a}')

    # gets the generated key
    A = int(pow(G, a, P))
    print(f'The public key A for Alice is: {A}')

    # Bob will choose the private key b
    b = randint(5, 25)
    print(f'The private key b for Bob is: {b}')

    # gets the generated key
    B = int(pow(G, b, P))
    print(f'The public key B for Bob is: {B}')

    # Secret key for Alice
    ka = int(pow(B, a, P))

    # Secret key for Bob
    kb = int(pow(A, b, P))

    print(f'Secret key for the Alice is: {ka}')
    print(f'Secret key for the Bob is: {kb}')
