import functools
from random import randint


def get_num_of_parity_bits(data):
    # Uses the formula 2 ^ r >= m + r + 1
    data_len = len(data)
    for i in range(data_len):  # i = num of parity bits
        if 2 ** i >= data_len + i + 1:
            return i


def add_parity_bits(data, pr_amount):
    ret = ['X']  # data[:]
    d_len = len(data)

    p_pos = 0
    d_pos = 0
    for i in range(1, d_len + pr_amount + 1):
        if i == 2 ** p_pos:
            ret += ['x']
            p_pos += 1
        else:
            ret += [data[d_pos]]
            d_pos += 1

    # print(ret, len(ret))
    print_matrix(list(ret), pr_amount)


    ret = calc_parity_bits(ret, pr_amount)
    return ''.join(ret)


def calc_parity_bits(data, pr_amount):
    d_len = len(data)

    for i in range(pr_amount):
        parity = 0
        for z in range(3, d_len):
            if z == 2 ** (i):
                continue
            if (2 ** (i) == 2 ** (i) & z):
                parity ^= int(data[z])

        print(f'parity of parity bit #{i + 1} = {parity}')

        data[2 ** (i)] = f'{parity}'

    parity = 0
    for i in range(1, d_len):
        parity ^= int(data[i])
    data[0] = f'{parity}'
    print(f'\nparity of parity bit #0 = {parity}')

    return data


def detect_error(data):
    # checking the parity bits
    err = functools.reduce(lambda x, y: x^y,
                           [int(index) for index, val in enumerate(data) if val == '1'])
    if err == 0:
        return 0 # no errors were found

    # checking the parity of the whole block:
    block_parity = len([i for i in data if i == '1']) % 2

    if block_parity == 0 and err != 0:  # if detected an error but the block's parity was fine
        return -1 # there is more than one error

    return err  # index of where the error is



def print_matrix(d, row_num):
    temp = []
    for i in range(row_num):
        temp.append(d[row_num*i:row_num*(i+1)])

    for i in temp:
        print(i)


if __name__ == '__main__':
    d = '11011010100'
    d = add_parity_bits(d, get_num_of_parity_bits(d))

    d = list(d)

    print()
    print_matrix(d, 4)

    print()
    print()
    print()

    for i in range(8):
        temp = d[:]
        print(f'\ngoing to change {i} bits')

        already_changed = []
        for i in range(i):
            x = randint(0, len(temp) - 1)
            while x in already_changed:
                x = randint(0, len(temp) - 1)

            print(f'changing bit at index {x}')
            already_changed.append(x)

            temp[x] = chr(ord(temp[x]) ^ 1)  # changes 1 -> 0 and 0 -> 1

        print_matrix(temp, 4)

        err = detect_error(temp)
        if err == 0:
            print('No errors detected!')
        elif err == -1:
            print('More than one error detected')
        else:
            print(f'error at {err}')


    print()
    print()
    temp = d[:]

    temp[7] = chr(ord(temp[7]) ^ 1)
    temp[11] = chr(ord(temp[11]) ^ 1)

    print_matrix(temp, 4)

    err = detect_error(temp)
    if err == 0:
        print('No errors detected!')
    elif err == -1:
        print('More than one error detected')
    else:
        print(f'error at {err}')