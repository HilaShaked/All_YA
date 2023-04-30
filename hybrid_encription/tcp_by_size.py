import socket, struct

SIZE_HEADER_FORMAT = "00000000"  # n digits for data size
size_header_size = len(SIZE_HEADER_FORMAT)
TCP_DEBUG = True


def recv_by_size(sock, *, addition_before = None, addition_after = '', down_a_line = True, return_type="string"):
    """
    ** returns a tuple with the message received and the size (so I could send size related errors) **
    """

    """Get len of message"""
    str_size, data_len = b"", 0
    while len(str_size) < size_header_size:
        try:
            _d = sock.recv(size_header_size - len(str_size))
        except ConnectionResetError:
            return b'', 0

        if len(_d) == 0:  # if not all the size of the message arrived
            str_size = b""
            break
        str_size += _d

    if str_size == b"":  # if it is empty, it will not get into the other ifs and send
        return b'', 0

    data = b""
    str_size = str_size.decode()

    """Get message"""
    if str_size != "":
        data_len = int(str_size)
        while len(data) < data_len:
            _d = sock.recv(data_len - len(data))
            if len(_d) == 0:
                data = b""
                break
            data += _d

    """log"""
    if TCP_DEBUG and len(str_size) > 0 and isinstance(str_size, str):
        data_to_print = data[:100]
        if type(data_to_print) == bytes:
            try:
                data_to_print = data_to_print.decode()
            except (UnicodeDecodeError, AttributeError):
                pass
        if down_a_line:
            print()
        if addition_before is not None:
            print(addition_before, end='')
        print(f"Receive({str_size}){addition_after}<<<{data_to_print}")


    if data_len != len(data):
        data = b""  # Partial data is like no data !
    if return_type == "string":
        return data.decode(), data_len
    return data, data_len


def send_with_size(sock, data, *, down_a_line = True, addition_before = ''):
    len_data = str(len(data)).zfill(size_header_size)  # get len of data
    len_data = len_data.encode()
    if type(data) != bytes:  # encode data if necessary
        data = data.encode()
    data = len_data + data
    sock.send(data)

    "log: "
    if TCP_DEBUG and len(len_data) > 0:
        data = data[:100]
        if type(data) == bytes:
            try:
                data = data.decode()
            except (UnicodeDecodeError, AttributeError):
                pass
        if down_a_line:
            print()
        print(f"{addition_before}Sent({len_data})>>>{data[8:]}\n")

