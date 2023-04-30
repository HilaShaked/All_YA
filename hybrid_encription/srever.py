import socket
import threading
import traceback
from random import randint
from sympy import randprime
from tcp_by_size import recv_by_size, send_with_size
from the_encryption_stuff import calc_d, calc_e, decode_pms
from the_encryption_stuff import prim_roots
from the_encryption_stuff import make_AES_key, AES_decrypt, AES_encrypt



KILL_ALL = False  # noqa
FIELD_SEP = '@|@'


the_worst_data_base = {'temp': '123456'}  # it cannot have 2 users with the same name

"""
Protocol: for login/sign in

field separator = '@|@'

------------------------------
Key exchange part:
******************
From client:
CHELO (client hello) = start of key exchange with RSA. fields: 1- a random number
CKEYX (client key exchange) = after 'SHELO' message from server. fields: 1- the encrypted premaster secret


CKDIF = (client key Diffie Hellman) key exchange with Diffie Hellman. no additional fields


----------------

From server:
SHELO (server hello) = after 'CHELO' from client. fields: 1- a random number, 2- the n of server's public key
                                                                                3- the e of server's public key 
SRFIN (server finish) = an ack after client's 'CKEYX' message. fields: 1- 'Finished RSA key exchange'




------------------------------
everything else:
****************

From client:
LOGIN (login) = want to log in with existing username and password. fields: 1- username, 2- password
SINUP (sign up) = want to sign up with new username and password. fields: 1- username, 2- password

MESG (message) = message from client.  fields: 1- username who send the message, 2- the message
----------------
From server:

ACSES (access) = weather or not the user can enter. fields: 1- 'True' or 'False', 2- message (can be an empy message)


------------------------------
ERROR - can be from both. means an error has occurred. fields: 1- additional message

ACK = acknowledgement that what was sent was received.  fields: 1- additional message

"""


def RSA(sock, addr, num_from_cli):  # noqa
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
    # ran_num = randint(321, 626232)
    ran_num = randint(300, 1000)

    send_data(sock, addr, ('SHELO', ran_num, n, e))

    data = receive_from_client(sock, addr, return_size=False, decode=False)
    if data is None:
        return

    reply = parse_receive(data)[0]
    print(f'Debug: reply = {reply}')

    if reply is None:
        return

    pms = decode_pms(reply, d, n)
    print(f'Debug: Got out')
    print(f'Debug: pms = {pms}')

    send_data(sock, addr, ('SRFIN', 'Finished RSA key exchange'))

    return make_AES_key(pms, num_from_cli, ran_num)


def diffie_hellman(sock):
    P = randprime(500, 1000)  # noqa
    # print(P)
    roots = prim_roots(P)
    G = roots[randint(0, len(roots) - 1)]  # noqa

    # send P and G
    # client also calc private and public keys

    private_key = randint(42, 23651)  # 657
    public_key = int(pow(G, private_key, P))

    # send public k
    #


def send_data(sock, addr, to_send, key=0) -> bool:
    """
    returns if sending was successful
    """
    sending = []
    for i in to_send:
        if not isinstance(i, str):
            i = str(i)
        sending += [i]
    to_send = FIELD_SEP.join(sending)
    if key != 0:
        to_send = AES_encrypt(to_send, key)

    try:
        send_with_size(sock, to_send, addition_before=f'{addr}: ')
        return True
    except ConnectionError:
        print(f'Client {addr} disconnected')
        return False


def parse_receive(data) -> tuple:
    try:
        if not isinstance(data, bytes):
            fields = data.split(FIELD_SEP)
        else:
            fields = data.decode().split(FIELD_SEP)
        code = fields[0]


        if code == 'CHELO':  # noqa
            num = int(fields[1])
            return 'RSA', num
        elif code == 'CKEYX':
            return fields[1],

        elif code == 'CKDIF':
            return 'DIFF',

        elif code == 'ACK':
            return 'Ack', fields[1]

        elif code in ['LOGIN', 'SINUP']:
            username = fields[1]
            password = fields[2]
            return code.lower(), username, password

        elif code == 'MESG':
            name, msg = fields[1], fields[2]
            return 'M', name, msg

    except Exception as e:
        print(f'Client replay bad format: {e}')
    return None,



def check_length(message, size_gotten):  # noqa
    """
    check message length
    return: string - error message
    """
    size = len(message)
    if size < 4:  # 17 is min message size
        return f'ERROR{FIELD_SEP}Bad Format. Message too short'.encode()
    if size_gotten != size:
        return f'ERROR{FIELD_SEP}Bad Format. Incorrect message length'.encode()
    return b''


def sign_up(username, password) -> bool:
    """
    :return: False if there is already a user with the same name
    """
    if username in the_worst_data_base:
        return False

    the_worst_data_base[username] = password
    return True


def login(sock, addr, key):  # noqa
    """
    :return: None if client disconnected. True if client username and password in database, False if not
    it returns a tuple: (None, 0, ''), (False, 0, *message*), (True, *username*, '')...
    """
    print(f'Debug: In "login"')
    print(f'Debug: Data base = {the_worst_data_base}')


    data = receive_from_client(sock, addr, return_size=False, decode=True, key=key)  # noqa
    if data is None:
        return None, 0, ''

    x, username, password = parse_receive(data)

    print(f'Debug: user = {username}, pass = {password}, x = {x}')

    if x == 'login' and username in the_worst_data_base and the_worst_data_base[username] == password:
        return True, username, ''

    elif x == 'sinup':
        if sign_up(username, password):
            print(f'Debug: Data base = {the_worst_data_base}')
            return True, username, ''
        print(f'Debug: Data base = {the_worst_data_base}')
        return False, 0, "Username already exists"


    return False, 0, "username or password are incorrect"  # noqa


def handle_client_request(request: tuple):
    if request[0] == 'M':
        print(f'\n\nGot message from "{request[1]}": {request[-1]}')
        return 'ACK', 'Got the message'

    elif request[0] == 'A':
        print(f'Got ACK. {request[1]}')

    return 'ERROR', 'Invalid request'


def key_exchange(sock, addr):
    data = receive_from_client(sock, addr, return_size=False, decode=False)
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


def receive_from_client(sock, addr, *, return_size=True, decode=True, key=0):
    try:
        if decode:
            data, size = recv_by_size(sock, addition_before=f'{addr}: ', return_type='not string')
        else:
            data, size = recv_by_size(sock, addition_before=f'{addr}: ')
    except ConnectionError:
        data, size = b'', 0

    if data == b'' and size == 0:
        data = None
    elif decode:
        data = AES_decrypt(data, key)
        print(f'Debug: data = {data}')

    if return_size:
        return data, size
    return data


def handle_client(sock, addr):
    ""
    """key exchange part"""
    print(f'\n\nNew Client Connected {addr}')
    key = key_exchange(sock, addr)

    """login part"""
    can_enter = 0
    if key is None:
        print(f'---\nNo key from client {addr}\n---')
    else:
        while (can_enter is not None) and (not can_enter):  # סוגריים כדי שיהיה נוח לקרוא
            can_enter, username, msg = login(sock, addr, key)
            print(f'Debug: can_enter = {can_enter}, user = {username}')
            if can_enter is None:
                break

            to_send = ('ACSES', can_enter, msg)
            send_data(sock, addr, to_send)

            data = receive_from_client(sock, addr, key=key, return_size=False)
            data = parse_receive(data)
            if data[0] is None:
                print(f'Seems that client {addr} disconnected')
                can_enter = False
            handle_client_request(data)



    """communication part"""  # noqa
    while can_enter:
        if KILL_ALL:
            print(f'closing connection with {addr}')
            break
        try:
            data, size = receive_from_client(sock, addr, key=key)
            if data is None:
                print('Seems client disconnected')
                break
            # logtcp('recv', tid, data)
            err_size = check_length(data, size)
            if err_size != b'':
                to_send = err_size
            else:
                to_send = handle_client_request(parse_receive(data))

            if to_send != '':
                send_data(sock, addr, to_send, key=key)

        except socket.error as err:
            print(f'Socket Error exit client loop: err:  {err}')
            break
        except Exception as err:
            print(f'General Error %s exit client loop: {err}')
            print(traceback.format_exc())
            break


    print(f'Client {addr} Exit')  # noqa
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
        except:  # noqa
            break


    print('Main thread: waiting to all clients to die')  # noqa
    for t in threads:
        t.join()

    srv_sock.close()
    print('Bye ..')


if __name__ == '__main__':
    main()
