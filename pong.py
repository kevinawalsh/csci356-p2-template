#!/usr/bin/env python3

import os, sys, socket, socketutil

server_host = "" # blank means listen on any available network interface
server_port = 8005

if len(sys.argv) > 2:
    print("usage:")
    print("   %s [server_port]" % (sys.argv[0]))
    exit()

if len(sys.argv) > 1:
    server_port = int(sys.argv[1])
server_addr = (server_host, server_port)

print("Listening on address %s:%d" % (server_host, server_port))

s = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(server_addr)
s.listen(5)

try:
    while True:
        sock, client_addr = s.accept()
        print("got connection from client %s:%s" % (client_addr))
        while True:
            val = int(sock.recv_line())
            print("client says: %d" % (val))
            result = val * val
            sock.sendall(str(result) +"\n")
            if val == 1:
                break
        sock.close()
finally:
    s.close()
