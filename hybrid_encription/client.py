import sys
import socket
from random import randint
import tkinter as tk
from tkinter import ttk
from tcp_by_size import recv_by_size, send_with_size


field_sep = '@|@'
PORT = 1234

aaaa: tk.OptionMenu #or None #= None  # noqa
option = None

enter = False


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
    list_of_entries[2]['command'] = lambda: send_loging(list_of_entries[0].get(), list_of_entries[1].get(), sock)
    list_of_entries[5]['command'] = lambda: send_sign_up(list_of_entries[3].get(), list_of_entries[4].get(), sock)


    # root.mainloop()  # noqa E303



def send_loging(name: str, pass_: str, sock):
    print(name, pass_, 'log')
    if name.strip() != '' and pass_.strip() != '':
        # send_with_size(sock, '')
        exchange_key(sock, )

def send_sign_up(name, pass_, sock):  # noqa E302
    print(name, pass_, 'sin')
    if name.strip() != '' and pass_.strip() != '':
        # send_with_size(sock, '')
        exchange_key(sock, )



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


def exchange_key(sock):
    print(option.get())
    



def login_screen(root):  # noqa E303
    login = tk.Label(root, text='Log In', font=('Calibri', 24), bg=root['bg'])
    # login.place(relx = 0.25, rely = 0.2, anchor ='nw')
    login.place(relx=0.5, rely=0.2, anchor='n')

    label = tk.Label(root, text="Don't have an account? ")
    sign_up = tk.Button(root, text="Sign up", command=lambda: sign_up_screen(root))


    label.place(relx=0.5, rely=0.9, anchor='s')  # noqa E303
    sign_up.place(relx=0.6, rely=0.905, anchor='s')

    root.mainloop()


def sign_up_screen(root):
    sign_up = tk.Label(root, text='sign_up', font=('Calibri', 24), bg='light blue')

    sign_up.place(relx=0.68, rely=0.2, anchor='nw')
    print('worked')


def main(ip):
    # connect to server:
    s = socket.socket()
    s.connect((ip, PORT))

    login_and_sign_up_win(s)
    print('...')




if __name__ == '__main__':  # noqa E303
    serv_ip = '127.0.0.1'
    if len(sys.argv) > 1:
        serv_ip = sys.argv[1]

    i = 0
    while not enter and i < 10:
        i += 1
        try:
            main(serv_ip)
            enter = True
        except WindowsError as e:
            if e and e.winerror == 10061:
                # print('Could not connect to the server')
                print('.', end=' ')
            else:
                print(f'Error: {e}')
        except Exception as e:
            print(f'Error: {e}')

    if i == 10 and not enter:
        print('Could not connect to the server')

"""
meep
-meep-
-a
"""
