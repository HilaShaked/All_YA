import socket
import threading
import traceback
from random import randint
from sympy import randprime
from tcp_by_size import recv_by_size, send_with_size
from the_encryption_stuff import calc_d, calc_e, decode_pms
from the_encryption_stuff import prim_roots
from the_encryption_stuff import  make_AES_key, AES_decrypt, AES_encrypt



KILL_ALL = False
FIELD_SEP = '@|@'

"""
Protocol: for login/sign in

field separator = '@|@'

------------------------------
Key exchange part:

From client:
CHELO (client hello) = start of key exchange with RSA. fields: 1- a random number
CKEYX (client key exchange) = after 'SHELO' message from server. fields: 1- the encrypted premaster secret


CKDIF = (client key Diffie Hellman) key exchange with Diffie Hellman. no additional fields

----------------

from server:
SHELO (server hello) = after 'CHELO' from client. fields: 1- a random number, 2- the n of server's public key
                                                                                3- the e of server's public key 
SRFIN (server finish) = an ack after client's 'CKEYX' message. fields: 1- 'Finished RSA key exchange'


------------------------------
everything else:


"""


def RSA(sock, addr, num_from_cli):
    # p = randprime(300, 5000)
    p = randprime(50, 300)
    # q = randprime(300, 5000)
    q = randprime(50, 300)
    n = p * q
    phi = (p-1)*(q-1)

    e = calc_e(phi)
    d = calc_d(e, phi)

    public_key = (n, e)
    private_key = (n, d)

    print('public: ', public_key, 'private: ', private_key)
    # print(f'e: {e}, phi: {phi}')
    ran_num = randint(321, 626232)

    send_data(sock, ('SHELO', ran_num, n, e))

    data = receive_from_client(sock, addr, False)
    if data is None:
        return

    reply = parse_receive(data)[0]
    print(f'Debug: reply = {reply}')

    if reply is None:
        return

    pms = decode_pms(reply, d, n)
    print(f'Debug: Got out')
    print(f'Debug: pms = {pms}')

    return make_AES_key(pms, num_from_cli, ran_num)


def diffie_hellman(sock):
    P = randprime(500, 1000)
    # print(P)
    roots = prim_roots(P)
    G = roots[randint(0, len(roots) - 1)]

    # send P and G
    # client also calc private and public keys

    private_key = randint(42, 23651)  # 657
    public_key = int(pow(G, private_key, P))

    # send public k
    #


def send_data(sock, to_send):
    sending = []
    for i in to_send:
        if not isinstance(i, str):
            i = str(i)
        sending += [i]
    to_send = FIELD_SEP.join(sending)
    send_with_size(sock, to_send)


def parse_receive(data) -> tuple:
    try:
        if not isinstance(data, bytes):
            fields = data.split(FIELD_SEP)
        else:
            fields = data.decode().split(FIELD_SEP)
        code = fields[0]


        if code == 'CHELO':
            num = int(fields[1])
            return 'RSA', num
        elif code == 'CKEYX':
            x = fields[1]
            return (x, )

        elif code == 'CKDIF':
            return ('DIFF',)

    except Exception as e:
        print(f'Client replay bad format: {e}')
    return (None, )




def check_length(message, size_gotten):
    """
    check message length
    return: string - error message
    """
    size = len(message)
    if size < 4:  # 17 is min message size
        return f'ERRO{FIELD_SEP}Bad Format. Message too short'.encode()
    if size_gotten != size:
        return f'ERRO{FIELD_SEP}Bad Format. Incorrect message length'.encode()
    return b''



def login(sock, key):
    """
    :return: None if client disconnected. True if client username and password in database, False if not
    """

    pass


def key_exchange(sock, addr):
    data = receive_from_client(sock, addr, False)
    if data is None:
        return

    reply = parse_receive(data)
    # gets a string: 'RSA' if with RSA, 'DIFF' if with Diffie-Hellman
    if reply[0] == 'RSA':
        return RSA(sock, addr, reply[1])
    elif reply[0] == 'DIFF':
        return diffie_hellman(sock)
    else:
        return None


def receive_from_client(sock, addr, return_size = True):
    data, size = recv_by_size(sock, addition_before=f'From {addr}: ')
    if data == b'' and size == 0:
        data = None

    if return_size:
        return data, size
    return data


def handle_client(sock, addr):
    print(f'\n\nNew Client Connected {addr}')
    key = key_exchange(sock, addr)
    can_enter = False
    if key == None:
        print('No key from client')
    else:
        while (not can_enter is None) and (not can_enter):  # סוגריים כדי שיהיה נוח לקרוא
            can_enter = login(sock, key)


    while can_enter:
        if KILL_ALL:
            print(f'closing connection with {addr}')
            break
        try:
            data, size = receive_from_client(sock, addr)
            if data is None:
                print('Seems client disconnected')
                break
            # logtcp('recv', tid, data)
            err_size = check_length(data, size)
            if err_size != b'':
                to_send = err_size
            else:
                to_send = parse_receive(data)

            if to_send != '':
                send_data(sock, to_send)

        except socket.error as err:
            print(f'Socket Error exit client loop: err:  {err}')
            break
        except Exception as err:
            print(f'General Error %s exit client loop: {err}')
            print(traceback.format_exc())
            break


    print(f'Client {addr} Exit')
    sock.close()


def main():
    # t = datetime.datetime.now()
    # diffie_hellman()
    # print(datetime.datetime.now() - t)
    threads = []
    srv_sock = socket.socket()

    srv_sock.bind(('0.0.0.0', 1234))

    srv_sock.listen(20)

    i = 1
    while True:
        try:
            print('\nMain thread: before accepting ...')
            cli_sock, addr = srv_sock.accept()
            t = threading.Thread(target=handle_client, args=(cli_sock, addr))
            t.start()
            i += 1
            threads.append(t)
        except:
            break


    print('Main thread: waiting to all clients to die')
    for t in threads:
        t.join()

    srv_sock.close()
    print('Bye ..')


if __name__ == '__main__':
    main()
