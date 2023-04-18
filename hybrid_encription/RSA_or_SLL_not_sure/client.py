import ssl
import socket

# create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# enable SSL on the socket
ssl_sock = ssl.wrap_socket(s,
                           ca_certs=r'ca_cert.pem',
                           cert_reqs=ssl.CERT_REQUIRED)

# connect to the server
ssl_sock.connect(("127.0.0.1", 443))

# send some data
ssl_sock.send(b"Hello, SSL Server!")

# receive and print the server's response
data = ssl_sock.recv(1024)
print("Received: ", data)

# close the connection
ssl_sock.close()
