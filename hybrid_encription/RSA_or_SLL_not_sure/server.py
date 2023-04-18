import ssl
import socket

# create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the socket to a specific address and port
s.bind(("0.0.0.0", 443))

# enable SSL on the socket
ssl_sock = ssl.wrap_socket(s,
                           certfile=r'cer.pem',
                           keyfile=r'key.pem',
                           server_side=True)

# listen for incoming connections
ssl_sock.listen()
print("Listening for SSL connections on 443...")

# accept a connection
conn, addr = ssl_sock.accept()
print("Connection from: ",addr)

# do something with the connection
while True:
    data = conn.recv(1024)
    if not data:
        break
    conn.send(data)

# close the connection
conn.close()