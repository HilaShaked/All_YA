def encrypt(text, key):
    # alphabet = ''.join([chr(i) for i in range(97, 123)])
    # print(alphabet)
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    cap_alphabet = alphabet.upper()

    ret = ''
    for i in text:
        if i in alphabet:
            ret += alphabet[(alphabet.find(i) + key) % 26]
        elif i in cap_alphabet:
            ret += cap_alphabet[(cap_alphabet.find(i) + key) % 26]
        else:
            ret += i

    return ret


def decrypt(text, key):
    return encrypt(text, -key)

# x = encrypt('beep', 0)
# y = encrypt('beep', 1)
# z = encrypt('beep', -1)
#
# print(x, y, z)
#
# x = encrypt("Hello! How's it going?", 8)
# print(x)
# print(encrypt(x, -8))

with open('ex2_cipher.txt', 'r') as f:
    cont = f.read()


for i in range(1, 27):
    print(f'key: {i}', decrypt(cont, i))


# correct one is key 21

