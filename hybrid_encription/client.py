import sys
import socket
import tkinter
from random import randint
import tkinter as tk
from tkinter import ttk
from tcp_by_size import recv_by_size, send_with_size
from the_encryption_stuff import make_AES_key, AES_encrypt, AES_decrypt


FIELD_SEP = '@|@'
PORT = 1234

aaaa: tk.OptionMenu #or None #= None  # noqa
option: tk.StringVar

entry_granted: bool = False


key = 0

server_disconnect = False

user_name = ''


def center_window(win):
    # make sure the geometry is updated
    win.update_idletasks()
    # print(win.geometry())

    # height and width of the computer screen
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()

    # current height and width of window
    window_width = win.winfo_width()
    window_height = win.winfo_height()


    center_x = int(screen_width / 2 - window_width / 2)
    center_y = int(screen_height / 2 - window_height / 2)

    # set new geometry
    win.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')


def login_and_sign_up_win(sock):
    # create the window:
    root = tk.Tk()
    root.title('Login screen')

    root.geometry(f'{1000}x{600}')
    center_window(root)

    frame = tk.Frame(root)
    frame['bg'] = 'light blue'
    frame.config(cursor='dot')  # just cuz I find it fun

    frame.pack(expand=True, fill=tk.BOTH)

    add_the_key_exchange_options(frame)


    login = tk.Label(frame, text='Login', font=('Calibri', 32), bg=frame['bg'])  # noqa E303
    login.place(relx=0.2, rely=0.2, anchor='nw')


    list_of_entries = make_login_labels_and_entries(frame, 0.2)  # noqa E303

    separator = ttk.Separator(frame, orient='vertical')  # .grid(row=8, column=5, rowspan=8, sticky='s')
    separator.pack(fill='y', padx=100, pady=20, expand=True)
    # separator.pack(fill='y')

    sign_up = tk.Label(frame, text='Sign up', font=('Calibri', 32), bg=frame['bg'])
    sign_up.place(relx=0.68, rely=0.2, anchor='nw')

    list_of_entries += make_login_labels_and_entries(frame, 0.7)
    # notebook = ttk.Notebook(frame)
    # notebook.pack(pady=100, padx=40, expand=True, fill=tk.BOTH)
    #
    # frame1 = ttk.Frame(notebook, width=400, height=280)
    # frame2 = ttk.Frame(notebook, width=400, height=280)
    #
    #
    #
    # frame1.pack(fill='both', expand=True)
    # frame2.pack(fill='both', expand=True)
    #
    # # add frames to notebook
    #
    # notebook.add(frame1, text='login')
    # notebook.add(frame2, text='sign up')


    # login_screen(frame)   # noqa E303
    print(list_of_entries)
    list_of_entries[2]['command'] = lambda: loging(list_of_entries[0].get(), list_of_entries[1].get(), sock, root)
    list_of_entries[5]['command'] = lambda: loging(list_of_entries[0].get(), list_of_entries[1].get(), sock, root, True)
    # list_of_entries[5]['command'] = lambda: send_sign_up(list_of_entries[3].get(), list_of_entries[4].get(), sock, root)



    root.mainloop()  # noqa E303


def add_the_key_exchange_options(root):  # noqa E303
    global option

    # since it's always visible
    label1 = tk.Label(root, text='select key exchange method: ', font=('Calibri', 16), bg='light blue')
    label1.place(relx=0.31, rely=0.045, anchor='nw')
    # label1.pack(ipadx=5, ipady=10)
    # label1.pack()
    options = ['Diffie Hellman', 'RSA']
    option = tk.StringVar(root, options[0])
    option_menu = tk.OptionMenu(root, option, *options)
    # option_menu['direction'] = 'right'
    option_menu['relief'] = 'groov'
    # paddings = {'padx': 5, 'pady': 5}
    # option_menu.grid(column=1, row=1, sticky=tk.E, **paddings)
    option_menu.place(relx=0.58, rely=0.05, anchor='nw')
    # option_menu.pack()
    # separator = ttk.Separator(root, orient='horizontal')
    separator = ttk.Separator(root, orient='horizontal')
    separator.pack(fill='x', pady=70)

    global aaaa
    aaaa = option_menu


def make_login_labels_and_entries(root, xpos):
    """
    makes and places the 'username' and 'password' labels and entries and the 'submit' button
    return a list of both entries: [username, password, button]
    """

    # label1 = tk.Label(root, text='select key exchange method: ', font=('Calibri', 16), bg='light blue')
    # label1.place(relx=0.31, rely=0.830, anchor='nw')
    # options = ['Diffie Hellman', 'RSA']
    # option_menu = tk.OptionMenu(root, tk.StringVar(root, options[0]), *options)
    # option_menu['relief'] = 'groov'
    # option_menu.place(relx=0.58, rely=0.83, anchor='nw')
    # separator = ttk.Separator(root, orient='horizontal')
    # separator.pack(fill='x', pady=290)

    label_username = tk.Label(root, text='Username: ', font=('Calibri', 24), bg=root['bg'])
    # label_username.place(relx=0.14, rely=0.35, anchor='nw')
    label_username.place(relx=xpos-0.11, rely=0.35, anchor='nw')

    username = tk.Entry(root, textvariable=tk.StringVar(), font=('Calibri', 16))
    # username.place(relx=0.3, rely=0.365, anchor='nw', width=160, height=30)
    username.place(relx=xpos+0.05, rely=0.365, anchor='nw', width=160, height=30)


    label_password = tk.Label(root, text='Password: ', font=('Calibri', 24), bg=root['bg'])  # noqa E303
    # label_password.place(relx=0.14, rely=0.45, anchor='nw')
    label_password.place(relx=xpos-0.11, rely=0.45, anchor='nw')

    password = tk.Entry(root, textvariable=tk.StringVar(), font=('Calibri', 16))
    # password.place(relx=0.3, rely=0.466, anchor='nw', width=160, height=30)
    password.place(relx=xpos+0.05, rely=0.466, anchor='nw', width=160, height=30)


    submit = tk.Button(root, font=('Calibri', 16), text='submit')  # noqa E303
    submit.place(relx=xpos, rely=0.6, anchor='nw', width=100, height=30)


    return [username, password, submit]  # noqa E303


def make_server_error_screen(error_message):
    # print(len(error_message))
    if len(error_message) > 29:
        temp = error_message
        error_message = ''
        for i in range(1, len(temp) + 1):
            error_message += temp[i - 1]
            if i % 28 == 0:
                error_message += '\n'


    serv_error = tk.Tk()
    serv_error.title('server error')
    serv_error.geometry(f'{800}x{500}')
    serv_error.resizable(False, False)
    center_window(serv_error)
    frame = tk.Frame(serv_error)
    frame['bg'] = '#d37b9e'  # redish pinkish color

    frame.config(cursor='X_cursor')  # just cuz I find it fun
    frame.pack(expand=True, fill=tk.BOTH)

    err = tk.Label(frame, text=error_message, font=('Calibri', 32), bg=frame['bg'])
    err.pack(fill='x', padx=100, pady=100)

    butt = tk.Button(frame, font=('Calibri', 16), text='close')
    butt.place(relx=0.45, rely=0.6, anchor='nw', width=100, height=30)

    butt['command'] = serv_error.destroy

    serv_error.protocol("WM_DELETE_WINDOW", serv_error.destroy)

    serv_error.mainloop()



def loging(name: str, pass_: str, sock, root, actually_sign_up = False):
    global key, server_disconnect

    print('Debug: In "login"')

    if actually_sign_up:
        print(name, pass_, 'sin')
        to_send = 'sin'
    else:
        print(name, pass_, 'log')
        to_send = 'log'

    name = name.strip()
    pass_ = pass_.strip()
    if name == '' or pass_ == '':
        return

    to_send = to_send, name, pass_

    key = exchange_key(sock)

    if key is None:
        make_server_error_screen('Error at server')
        # root.destroy()
        server_disconnect = True
        return


    send_to_server(sock, to_send)



# def send_sign_up(name: str, pass_: str, sock, root):
#     global key
#
#     name = name.strip()
#     pass_ = pass_.strip()
#     if name == '' and pass_ == '':
#         return
#     key = exchange_key(root, sock)



def exchange_key(sock):  # , username, password
    global entry_granted
    global key

    print('Debug: In "exchange_key"')

    exchange_option = option.get()
    print(exchange_option)

    if exchange_option == 'RSA':
        key = RSA(sock)
    else:
        key = diffie_hellman(sock)

    return key



def RSA(sock):
    """
    :return: None if got nothing,
            usually returns key
    """
    print('Debug: In "RSA"')

    cli_num = randint(657, 23651)
    send_to_server(sock, ('CHELO', f'{cli_num}'), False)
    data, size = recv_by_size(sock, down_a_line=False)
    if data == '' and size == 0:  # if '' so the server disconnected
        return

    reply = handle_receive(data)


    print(f'Debugh: {reply}')
    if isinstance(reply, str):
        make_server_error_screen(reply)
        return

    srv_num, n, e = int(reply[0]), int(reply[1][0]), int(reply[1][1])
    print(f'Debug: num = {srv_num}, server key = {(n, e)}')

    # pms = randint(0, 2**(8*48))
    pms = randint(2, 2**48)
    temp = pms
    print(f'Debug: pms = {pms}')

    ciphertext = ''
    while pms != 0:
        i = pms%10
        pms //= 10
        ciphertext += f"{i**e % n}"

    print(f'Debug: ciphertext = {ciphertext}')

    send_to_server(sock, ('CKEYX', ciphertext), False)

    # restore pms:
    pms = temp
    # import pyaes, pbkdf2, binascii, os, secrets
    return make_AES_key(pms, cli_num, srv_num)


def diffie_hellman(sock):
    pass



def send_to_server(sock, cont: tuple, encode: bool = True):
    print('Debug: In "send_to_server"')

    cont = FIELD_SEP.join(cont)
    print(f'Debugh (before encrypt): {cont}')
    if encode:
        cont = AES_encrypt(cont, key)
        temp = AES_decrypt(cont, key)
        print(f'Debug (check if decrypt works): {temp}')

    print(f'Debug (after encrypt): {cont}')
    send_with_size(sock, cont)



def handle_receive(data):
    ret = 'Invalid reply from server'
    try:
        # reply = reply.decode()
        if not isinstance(data, bytes):
            fields = data.split(FIELD_SEP)
        else:
            fields = data.decode().split(FIELD_SEP)
        code = fields[0]


        if code in ['ACK', 'SRFIN']:
            ret = f'Ack. {fields[1]}'

        elif code == 'SHELO':
            num = fields[1]
            s_key = (fields[2], fields[3])
            return num, s_key

    except Exception as e:
        print(f'Server replay bad format: {e}')
    return ret


def communicate(sock):
    print('Enter nothing to exit')
    i = input(f'{user_name} send > ')
    while i != '':
        send_to_server(sock, (i,))
        i = input(f'{user_name} send > ')
    print('Finish sending...')


def main(ip):
    # connect to server:
    s = socket.socket()
    s.connect((ip, PORT))

    login_and_sign_up_win(s)
    print('Finished login')
    if not server_disconnect:
        if entry_granted:
            communicate(s)

    print('Bye!')



def get_into_server(serv_ip):
    i = 0
    connected = False
    while not connected and i < 10:
        i += 1
        try:
            main(serv_ip)
            connected = True
        except WindowsError as e:
            if e and e.winerror == 10061:
                # print('Could not connect to the server')
                print('.', end=' ')
            else:
                print(f'Error: {e}')
        except Exception as e:
            print(f'Error: {e}')

    if i == 10 and not connected:
        print('Could not connect to the server')


if __name__ == '__main__':  # noqa E303
    serv_ip = '127.0.0.1'
    if len(sys.argv) > 1:
        serv_ip = sys.argv[1]

    get_into_server(serv_ip)

"""
meep
-meep-
-a
"""
