from sympy import randprime
import pbkdf2
import pyaes


# for RSA:
def calc_d(e, phi):
    # (d*e)% phi = 1
    # d*e = phi*x + 1
    # d = (phi*x + 1) / e

    x = 3
    # print(x)
    d = (phi*x + 1) / e
    while d % 1 != 0:
        x += 1
        d = (phi*x + 1) / e
    # print('check', (d * e) % phi)
    # print(f'd: {d}, x: {x}')
    return int(d) # d should have a .0


def calc_e(phi):
    # e = randprime(300, 10000)
    e = randprime(50, 200)
    while phi % e == 0:
        # e = randprime(300, 10000)
        e = randprime(50, 200)

    return e


def encode_pms(pms, n, e):
    ciphertext = ''
    while pms != 0:
        i = pms % 10
        pms //= 10
        ciphertext = f"{i ** e % n}-" + ciphertext # to separate each num so I cloud decode it
        # cuz I don't know how you can decode it otherwise

    return ciphertext[:-1]


def decode_pms(ciphertext, d, n):
    # print(f'Debug: In "decode_pms"')

    pms = 0
    ciphertext = ciphertext.split('-')
    print(f'Debug: ciphertext = {ciphertext}')

    for i in ciphertext:
        # print(',', end=' ')
        pms *= 10
        pms += int(i)**d % n
        # print('.', end=' ')
    # print(f'Debug: num = {num}')
    return pms



# for diffie-hellman
def prime_roots(num):
    o = 1
    roots_ls = []
    r = 2
    while r < num:
        k = pow(r, o, num)
        while k > 1:
            o += 1
            k = (k * r) % num
        if o == (num - 1):
            roots_ls += [r]
        o = 1
        r = r + 1
    return roots_ls



# for AES
def make_AES_key(num, salt, iteration_num):
    key = pbkdf2.PBKDF2(f'{num}', f'{salt}', iteration_num).read(32)
    # print(len(key))

    return key


def AES_encrypt(msg, key):
    AES = pyaes.AESModeOfOperationCTR(key)
    return AES.encrypt(msg)


def AES_decrypt(msg, key):
    AES = pyaes.AESModeOfOperationCTR(key)
    return AES.decrypt(msg)

