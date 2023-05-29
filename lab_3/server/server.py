#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import datetime
import os

########################################################################
# Service Discovery Server
#
# The server listens on a UDP socket. When a service discovery packet
# arrives, it returns a response with the name of the service.
# 
########################################################################

class Client_RQ:
    client              = None
    request             = None
    request_str         = None
    name_remaining      = None
    data_remaining      = None
    data_header_rem     = 8
    buffer              = None
    f                   = None
    carry_over          = None
    def __init__(self, client):
        self.client = client
    
    def reset(self):
        self.request            = None
        self.request_str        = None
        self.name_remaining     = None
        self.data_remaining     = None
        self.buffer             = None
        self.data_header_rem    = 8
        self.f                  = None

    def clear_carry_over(self):
        self.carry_over         = None


class Server:

    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_SCAN_PORT = 30000
    UDP_ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_SCAN_PORT)

    SERVICE_TCP_PORT = 30001
    TCP_ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_TCP_PORT)


    MSG_ENCODING = "utf-8"    
    
    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)
    
    MSG = "Caleb, Zach, Jack, and Sophie's File Sharing Service: Service Port={a}".format(a=SERVICE_TCP_PORT)
    MSG_ENCODED = MSG.encode(MSG_ENCODING)

    RECV_SIZE_TCP_UDP = 17
    RECV_SIZE_TCP = 9
    BACKLOG = 10

    UDP_RECV_TIMEOUT = 0.1

    FILE_STREAM_BUFFER_SIZE = 1024
    PRINT_RECV_FILE_STREAM = False

    CMD = {
        "get" : b'\x01',
        "put" : b'\x02',
        "list" : b'\x03',
        }

    def __init__(self):
        self.create_socket()
        self.receive_forever()

    def create_socket(self):
        try:
            ##UDP
            # Create an IPv4 UDP socket.
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Get socket layer socket options.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            #set timeout for service disovery requests
            #self.udp_socket.settimeout(Server.UDP_RECV_TIMEOUT)

            ##nonblocking UDP
            self.udp_socket.setblocking(False)

            # Bind socket to socket address, i.e., IP address and port.
            self.udp_socket.bind( Server.UDP_ADDRESS_PORT )

            ##TCP
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.tcp_socket.bind( Server.TCP_ADDRESS_PORT )

            ############################################################
            # Set the (listen) socket to non-blocking mode.
            self.tcp_socket.setblocking(False)
            ############################################################            

            # Set socket to listen state.
            self.tcp_socket.listen(Server.BACKLOG)
            print("TCP Service Listening on port {} ...".format(Server.TCP_ADDRESS_PORT))
            print(72*"*")
            print(Server.MSG, "UDP service discovery listening on port {} ...".format(Server.SERVICE_SCAN_PORT))
            print(72*"*")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        # Keep a list of the current client connections.
        self.connected_clients = []
        
        while True:
            try:
                
                #UDP Handler
                try:
                    recvd_bytes, address = self.udp_socket.recvfrom(Server.RECV_SIZE_TCP_UDP)

                    print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
            
                    # Decode the received bytes back into strings.
                    recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                    # Check if the received packet contains a service scan
                    # command.
                    if Server.SCAN_CMD in recvd_str:
                        # Send the service advertisement message back to
                        # the client.
                        self.udp_socket.sendto(Server.MSG_ENCODED, address)
                except KeyboardInterrupt:
                    print()
                    sys.exit(1)
                except socket.error:
                    pass


                ##TCP Handler
                self.check_for_new_connections()
                self.service_connected_clients()
                
                


            except KeyboardInterrupt:
                print()
                sys.exit(1)

    def check_for_new_connections(self):
        try:
            # Check if a new connection is available.
            new_client = self.tcp_socket.accept()
            new_connection, new_address_port = new_client

            # Announce that a new connection has been accepted.
            print("\nConnection received from {}.".format(new_address_port))

            # Set the new socket to non-blocking. 
            new_connection.setblocking(False)

            # Add the new connection to our connected_clients
            # list.
            self.connected_clients.append(Client_RQ(new_client))
            
        except socket.error:
            # If an exception occurs, there are no new
            # connections. Continue on.
            pass

    def service_connected_clients(self):
        current_client_list = self.connected_clients.copy()

        for client in current_client_list:
            connection, address_port = client.client
            try:
                # Check for available incoming data.
                recvd_bytes = connection.recv(Server.RECV_SIZE_TCP)
                if self.PRINT_RECV_FILE_STREAM:
                    print(recvd_bytes)
                try:
                    recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                except UnicodeDecodeError as e:
                    recvd_str = "RAW"

                # Check if the client has said "bye" or if the client
                # has closed the connection.
                if recvd_str == "bye" or len(recvd_str) == 0:
                    print()
                    print("Closing {} connection ...".format(address_port))
                    self.connected_clients.remove(client)
                    connection.close()
                    continue
                if client.request      == None:
                    self.process_new_request(client, recvd_bytes)
                else:
                    if client.request == self.CMD["get"]:
                        client.name_remaining    -= len(recvd_bytes)
                        client.buffer       = client.buffer + recvd_bytes
                    elif client.request == self.CMD["put"]:
                        #get file name
                        if not client.name_remaining is None and client.name_remaining >= 0:
                            #print(1)
                            client.name_remaining    -= len(recvd_bytes)
                            client.buffer       = client.buffer + recvd_bytes 
                        
                        ##open file
                        if(not client.name_remaining is None and client.name_remaining <= 0 and client.f is None):
                            #print(2)
                            client.data_header_rem += client.name_remaining
                            
                            file_name = client.buffer[:len(client.buffer) + client.name_remaining].decode(Server.MSG_ENCODING) 
                            print("New file: ", file_name)
                            try:
                                if file_name[0] != '.':
                                    file_name = "./" + file_name
                                os.makedirs(os.path.dirname(file_name), exist_ok=True)
                                client.f = open(file_name, 'wb')
                            except Exception as e:
                                print(e)
                            client.buffer   = client.buffer[len(client.buffer) + client.name_remaining:]
                            client.name_remaining = None

                        ##get file size header (8-bytes)
                        elif client.data_header_rem > 0 and not client.f is None:
                            #print(3)
                            client.data_header_rem    -= len(recvd_bytes)
                            client.buffer       = client.buffer + recvd_bytes
                        
                        ##convert file size header to file size
                        if client.data_header_rem <= 0 and client.data_remaining is None:
                            #print(4)
                            client.data_remaining = int.from_bytes(client.buffer[:len(client.buffer) + client.data_header_rem], "big")
                            print("File size is (bytes): ", client.data_remaining)

                            ##file not found case
                            if int.from_bytes(client.buffer[:len(client.buffer) + client.data_header_rem], "big", signed=True) == -1:
                                printf("File Not Found!!")
                                os.unlink(client.f.name) #delet the file
                                client.f.close()
                                client.reset()
                                break

                            client.buffer   = client.buffer[len(client.buffer) + client.data_header_rem:]
                            ##write remaining buffer data to file and clear buffer
                            recvd_bytes = client.buffer
                            client.buffer = None
                        
                        ##write to file
                        if not client.f is None and not client.data_remaining is None and len(recvd_bytes) > 0: 
                            #print(5)
                            new_req_detect = False
                            client.data_remaining    -= len(recvd_bytes)
                            if(client.data_remaining < 0):
                                #check if a new request has come through
                                start_idx = client.data_remaining
                                end_idx = client.data_remaining+1
                                #python doesn't like [-1:0] slicing - just do [-1:]
                                if client.data_remaining == -1:
                                    first_overflow_byte = recvd_bytes[start_idx:]
                                else:
                                    first_overflow_byte = recvd_bytes[start_idx:end_idx]
                                #check if the first overflow byte is a command
                                if first_overflow_byte in self.CMD.values():
                                    new_req_detect = True
                                    client.carry_over = recvd_bytes[client.data_remaining:]
                                    recvd_bytes = recvd_bytes[:client.data_remaining]
                                    client.data_remaining = 0
                                    
                            #print(recvd_bytes, client.data_remaining)
                            client.f.write(recvd_bytes)
                            if(client.data_remaining == 0):
                                ##file recieved!
                                print("File transfer complete!")
                                client.f.close()
                                client.reset()
                            elif(client.data_remaining < 0 and not new_req_detect):
                                print("Something went wrong! Overflow Bytes:", client.data_remaining)
                                print("Overflow Data:",recvd_bytes[client.data_remaining:])
                                os.unlink(client.f.name) #delet the file
                                client.f.close()
                                client.reset()


                    elif client.request == self.CMD["list"]:
                        pass

                if not client.name_remaining is None and client.name_remaining == 0:
                    if client.request == self.CMD["get"]:
                        ##send file to client
                        file_size = 0
                        try:
                            f = open(client.buffer.decode(Server.MSG_ENCODING), 'rb')
                            f.seek(0, os.SEEK_END)
                            file_size = f.tell()
                            f.close()
                            self.send_8b_delim_message(client, file_size, self.get_handler_cb)
      
                        except Exception as e:
                            print(e)

                        client.reset()

                    ##print result to terminal
                    print('"'+str(client.request_str)+'"'+" file name recieved for client: ", address_port)
                    print("Buffer is:", client.buffer )
                elif(not client.name_remaining is None and client.name_remaining > 0):
                    print('"'+str(client.request_str)+'"'+" name_remaining:" + str(client.name_remaining)  +    " for client: ", address_port)
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass
    

    def process_new_request(self, client, recvd_bytes):
        #get string form of bytes - for ECHO
        try:
            recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
        except UnicodeDecodeError as e:
            recvd_str = "RAW"


        #if we have carry over from a previous recieve, append it and clear carry over
        if not client.carry_over is None:
            recvd_bytes = client.carry_over + recvd_bytes
            client.clear_carry_over()

        # Echo back what we received - added as a sanity check
        if recvd_str.split(":",1)[0] == "ECHO":
            connection.sendall(recvd_str.split(":",1)[1].encode(Server.MSG_ENCODING))
            print("\nEcho: ", recvd_str.split(":",1)[1])
        elif recvd_bytes[0:1] == self.CMD["get"]:
            client.request_str  = "get"
            client.request      = self.CMD[client.request_str]
            client.name_remaining    = int.from_bytes(recvd_bytes[1:2], "big") - len(recvd_bytes[2:])
            client.buffer       = recvd_bytes[2:]
        elif recvd_bytes[0:1] == self.CMD["put"]:
            client.request_str  = "put"
            client.request      = self.CMD[client.request_str]
            client.name_remaining    = int.from_bytes(recvd_bytes[1:2], "big") - len(recvd_bytes[2:])
            client.buffer       = recvd_bytes[2:]
        elif recvd_bytes[0:1] == self.CMD["list"]:
            client.request_str  = "list"
            client.request      = self.CMD[client.request_str]
            dir_str = ""
            for root, dirs, files in os.walk("."):
                for filename in files:
                    dir_str += os.path.join(root, filename) + '\n'
            dir_str = dir_str.encode(Server.MSG_ENCODING)
            client.buffer = dir_str
            self.send_8b_delim_message(client, len(dir_str), self.list_handler_cb)
            client.reset()

    def list_handler_cb(self, client):
        connection, address_port = client.client
        connection.sendall(client.buffer)

    def get_handler_cb(self, client):
        connection, address_port = client.client
        f = open(client.buffer.decode(Server.MSG_ENCODING), 'rb')
        stream = f.read(self.FILE_STREAM_BUFFER_SIZE)
        while(stream):
            print("Sending...")
            connection.sendall(stream)
            stream = f.read(self.FILE_STREAM_BUFFER_SIZE)
        f.close()

    def send_8b_delim_message(self, client, file_size, iter_callback):
        connection, address_port = client.client
        try:
            if file_size < 0:
                send_bytes = int(-1).to_bytes(8,'big', signed=True)
                connection.sendall(send_bytes)
            else:
                connection.sendall(int(file_size).to_bytes(8,'big'))
                iter_callback(client)
        except Exception as e:
            print(e)
            send_bytes = int(-1).to_bytes(8,'big', signed=True)
            connection.sendall(send_bytes)

            

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    Server()

########################################################################







