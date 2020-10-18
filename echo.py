#!/usr/bin/env python3

import os, sys, socket, socketutil

server_host = ""
server_port = 8888

if len(sys.argv) < 2:
    print("usage:")
    print("   %s client server_host [server_port]" % (sys.argv[0]))
    print("   %s server [server_port]" % (sys.argv[0]))
    exit()

is_client = (sys.argv[1] == "client")
is_server = (sys.argv[1] == "server")
if not (is_client or is_server):
    print("sorry, first argument should be 'client' or 'server'")
    exit()

if is_client:
    if len(sys.argv) <= 2:
        print("sorry, for client mode, you need to specify the the server host to connect to")
        exit()
    server_host = sys.argv[2]
    if len(sys.argv) > 3:
        server_port = int(sys.argv[3])
else:
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])

server_addr = (server_host, server_port)

if is_client:
    print("Starting echo client")
    print("Connecting to server at %s:%d" % (server_host, server_port))

    c = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(server_addr)

    c.sendall("hey there\n")
    resp = c.recv_line()
    print("server says '%s'" % (resp))
    c.close()

else:
    print("Starting echo server")
    print("Listening on address %s:%d" % (server_host, server_port))

    s = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(server_addr)
    s.listen(5)
    print("Ready for connections...")

    try:
        while True:
            sock, client_addr = s.accept()
            print("got connection from client %s:%s" % (client_addr))
            req = sock.recv_line()
            print("client says '%s'" % (req))
            sock.sendall("What do you mean " + req + "?\n")
            sock.close()
    finally:
        s.close()
