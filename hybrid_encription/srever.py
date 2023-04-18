import socket
import threading
import traceback
from random import randint
from sympy import randprime
from tcp_by_size import recv_by_size, send_with_size


KILL_ALL = False
field_sep = '@|@'

"""
Protocol: for login/sign in

field_seperator = '@|@'

------------------------------
Key exchange part:

From client:
CHELO (client hello) = start of key exchange with RSA. fields: 1- a random number
CKEYX (client key exchange) = after 'SHELO' message from server. fields: 1- the premaster secret


CKDIF = (client key Diffie Hellman) key exchange with Diffie Hellman. no additional fields

----------------

from server:
SHELO (server hello) = after 'CHELO' from client. fields: 1- a random number, 2- the n of server's public key
                                                                                3- the e of server's public key 
SRFIN (server finish) = an ack after client's 'CKEYX' message. no additional fields


------------------------------
everything else:


"""


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
    e = randprime(300, 10000)
    while phi % e == 0:
        e = randprime(300, 10000)

    return e


def RSA():
    p = randprime(300, 5000)
    q = randprime(300, 5000)
    n = p * q
    phi = (p-1)*(q-1)

    e = calc_e(phi)
    d = calc_d(e, phi)

    public_key = (n, e)
    private_key = (n, d)

    print(public_key, private_key)
    # print(f'e: {e}, phi: {phi}')



def prim_roots(num):
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


def diffie_hellman():
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
    pass


def handle_request(data):
    pass


def check_length(data, size):
    pass


def login(sock):

    pass


def key_exchange(sock):
    how_to_exchange = handle_request(recv_by_size(sock))



def handle_client(sock, addr):
    print(f'New Client Connected {addr}')
    key = key_exchange(sock)
    can_enter = False
    if key == None:
        print('No key from client')
    else:
        can_enter = login(sock)


    while can_enter:
        if KILL_ALL:
            print(f'closing connection with {addr}')
            break
        try:
            data, size = recv_by_size(sock, addition=" <<< RECV from {addr}:")
            if data == b'' and size == 0:  # cuz if got a partial message, the data turns to b'' even though the client did not disconnect
                print('Seems client disconnected')
                break
            # logtcp('recv', tid, data)
            err_size = check_length(data, size)
            if err_size != b'':
                to_send = err_size
            else:
                to_send = handle_request(data)

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
