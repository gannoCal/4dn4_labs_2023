
#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import datetime
import os

########################################################################
# Service Discovery
#
# In this version, the client broadcasts service discovery packets and
# receives server responses. After a broadcast, the client continues
# to receive responses until a socket timeout occurs, indicating that
# no more responses are available. This scan process is repeated a
# fixed number of times. The discovered services are then output.
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

    open_files = []


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
        self.display_files()
        self.create_socket()
        self.receive_forever()

    def display_files(self):
        dir_str = ""
        for root, dirs, files in os.walk("."):
            for filename in files:
                dir_str += os.path.join(root, filename) + '\n'
        print(dir_str)

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
                for f in self.open_files:
                    os.unlink(f)
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
                                self.open_files.append(client.f.name)
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
                                try:
                                    self.open_files.remove(client.f.name)
                                except:
                                    pass
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
# Service Discovery Client
########################################################################

class Client:

    RECV_SIZE = 1024
    MSG_ENCODING = "utf-8"    

    BROADCAST_ADDRESS = "255.255.255.255"
    # BROADCAST_ADDRESS = "192.168.1.255"    
    SERVICE_DISCOVERY_PORT = 30000
    SERVICE_DISCOVERY_ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_DISCOVERY_PORT)

    SCAN_CYCLES = 3
    SCAN_TIMEOUT = 2

    RECV_BUFFER_SIZE = 8 # Used for recv.
    MSG_ENCODING = "utf-8" # Unicode text encoding.

    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)

    FILE_STREAM_BUFFER_SIZE = 1024

    open_files = []

    CMD = {
        "get" : b'\x01',
        "put" : b'\x02',
        "list" : b'\x03',
        }


    def __init__(self):
        self.connected = False
        try:
            self.get_udp_socket()
            while(1):
                self.start_prompt()
        except Exception as msg:
            print(msg)
            sys.exit(1)
        #self.get_sockets()
        #self.scan_for_service()
        #self.use_service_if_found()


    def get_sockets():
        self.get_udp_socket()
        self.get_tcp_socket()

    def remove_empty_entries(self, str_arr):
        return [str_ for str_ in str_arr if (str_ != '')]

    def start_prompt(self):
        try:
            valid_command = False
            while(not valid_command):
                self.input_text = input("Enter a command:\n")
                print("Command entered: " + self.input_text)
                valid_command = True
                if(self.input_text == "scan"):
                    self.scan_for_service()
                elif(self.input_text[0:8] == "Connect "):
                    self.get_tcp_socket()
                    input_arr = self.remove_empty_entries(self.input_text.split(" "))
                    if(len(input_arr) < 3):
                        print("Invalid connect command: Connect <IP address> <port>")
                        valid_command = False
                        continue
                    elif(not input_arr[2].isdigit()):
                        print("Invalid connect command: Connect <IP address> <port>")
                        valid_command = False
                        continue
                    self.service_address = (input_arr[1], int(input_arr[2]))

                    self.connect_to_service()
                elif(self.input_text == "llist"):
                    for root, dirs, files in os.walk("."):
                        for filename in files:
                            print(os.path.join(root, filename))
                elif(self.input_text == "rlist"):
                    if self.connected:
                        self.process_rlist()
                    else:
                        print("Not yet connected! use 'Connect <IP address> <port>'")
                elif(self.input_text[0:4] == "put "):
                    if self.connected:
                        self.process_put()
                    else:
                        print("Not yet connected! use 'Connect <IP address> <port>'")
                elif(self.input_text[0:4] == "get "):
                    if self.connected:
                        self.process_get()
                    else:
                        print("Not yet connected! use 'Connect <IP address> <port>'")
                
                # start echo client - added as a sanity check
                elif(self.input_text == "echo"):
                    if self.connected:
                        self.send_console_input_forever()
                    else:
                        print("Not yet connected! use 'Connect <IP address> <port>'")
                elif(self.input_text == "bye"):
                    print(72*"*")
                    print("Closing server connection ... ")
                    self.tcp_socket.close()
                else:
                    print("Invalid Command. Try Again.")
                    valid_command = False
        except KeyboardInterrupt as msg:
            print(msg)
            sys.exit(1)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    
    def process_rlist_callback(self, recvd_bytes):
        self.rlist_bytes += recvd_bytes

    def process_rlist(self):
        send_bytes = self.CMD["list"]
        self.tcp_socket.sendall(send_bytes)
        try:
            self.rlist_bytes = b''
            self.recieve_8b_delim_message(self.process_rlist_callback)
            print(72*"*")
            print("remote directory:")
            print(self.rlist_bytes.decode(self.MSG_ENCODING))
            del self.rlist_bytes
        except Exception as e:
            print(e)



    def recieve_8b_delim_message(self, iter_callback):
        ##recieve
        recvd_msg_length = 0
        recvd_msg = b""
        msg_length = -2 
        file_not_found = False
        something_went_wrong = False

        try:
            while True:
                # Receive and print out text. The received bytes objects
                # must be decoded into string objects.
                recvd_bytes = self.tcp_socket.recv(Client.RECV_BUFFER_SIZE)
                #print("(recv: {})".format(recvd_bytes))

                # recv will block if nothing is available. If we receive
                # zero bytes, the connection has been closed from the
                # other end. In that case, close the connection on this
                # end and exit.
                if len(recvd_bytes) == 0:
                    print("Closing server connection ... ")
                    self.tcp_socket.close()
                    sys.exit(1)


                if msg_length == -2:
                    msg_length = int.from_bytes(recvd_bytes[0:8], 'big')
                    print("message length (bytes):", msg_length)
                    if int.from_bytes(recvd_bytes[0:8], 'big', signed=True) == -1:
                        file_not_found = True
                    recvd_bytes = recvd_bytes[8:]
                else:
                    if int.from_bytes(recvd_bytes[0:8], 'big', signed=True) == -1:
                        something_went_wrong = True


                if((recvd_msg_length % 1000) == 0):
                    print("{a} percent complete...".format(a=(int(recvd_msg_length*100/msg_length))))

                
                if file_not_found == True:
                    print("File not found!")
                    os.unlink(f.name) # delete opened file
                    break
                
                if something_went_wrong:
                    print("Something went wrong!")
                    break

                recvd_msg += recvd_bytes
                iter_callback(recvd_bytes)
                recvd_msg_length += len(recvd_bytes)
                if not recvd_msg_length < msg_length:
                    break
        except KeyboardInterrupt as msg:
            print(msg) 
            for f in self.open_files:
                os.unlink(f)
            sys.exit(1)

        except Exception as e:
            print(e)
            for f in self.open_files:
                os.unlink(f)



    def process_get_callback(self, recvd_bytes):
        self.f.write(recvd_bytes)

    def process_get(self):
        file_name = self.input_text.split(" ",1)[1]
        if(len(file_name.encode(self.MSG_ENCODING)) > 255):
            print("Error: File name too long (255 characters max.)")
            return
        send_bytes = self.CMD["get"] + int(len(file_name)).to_bytes(1, 'big') + file_name.encode(self.MSG_ENCODING)
        self.tcp_socket.sendall(send_bytes)

        try:
            self.f = open(file_name, 'wb')
            self.open_files.append(self.f.name)
            self.recieve_8b_delim_message(self.process_get_callback)
            self.open_files.remove(self.f.name)
            self.f.close()
            del self.f
        except Exception as e:
            print(e)



    def put_handler_cb(self):
        f = open(self.file_name, 'rb')
        stream = f.read(self.FILE_STREAM_BUFFER_SIZE)
        while(stream):
            print("Sending...")
            self.tcp_socket.sendall(stream)
            stream = f.read(self.FILE_STREAM_BUFFER_SIZE)
        f.close()

    def send_8b_delim_message(self, file_size, iter_callback):
        try:
            if file_size < 0:
                send_bytes = int(-1).to_bytes(8,'big', signed=True)
                self.tcp_socket.sendall(send_bytes)
            else:
                self.tcp_socket.sendall(int(file_size).to_bytes(8,'big'))
                iter_callback()
        except Exception as e:
            print(e)
            send_bytes = int(-1).to_bytes(8,'big', signed=True)
            self.tcp_socket.sendall(send_bytes)

    def process_put(self):
        file_name = self.input_text.split(" ",1)[1]
        if(len(file_name.encode(self.MSG_ENCODING)) > 255):
            print("Error: File name too long (255 characters max.)")
            return
        
        ##check if file exists
        try:
            self.f = open(file_name, 'rb')
        except Exception as e:
            print(e)
            return

        ##send the file name first
        send_bytes = self.CMD["put"] + int(len(file_name)).to_bytes(1, 'big') + file_name.encode(self.MSG_ENCODING)
        self.tcp_socket.sendall(send_bytes)

        ##send the file stream
        try:
            self.f.seek(0, os.SEEK_END)
            file_size = self.f.tell()
            self.f.close()
            self.file_name = file_name
            self.send_8b_delim_message(file_size, self.put_handler_cb)

            del self.file_name
            del self.f
        except Exception as e:
            print(e)

        
        
        


    def connect_to_service(self):
        try:
            # Connect to the server using its socket address tuple.
            self.tcp_socket.connect(self.service_address)
            print("Connected to \"{}\" on port {}".format(self.service_address[0], self.service_address[1]))
            self.connected = True
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                # If we get and error or keyboard interrupt, make sure
                # that we close the socket.
                self.tcp_socket.close()
                sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered, i.e., ignore blank lines.
        while True:
            self.input_text = input("Input: ")
            if self.input_text != "":
                self.input_text = "ECHO:"+self.input_text
                break


    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.tcp_socket.sendall(self.input_text.encode(self.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.tcp_socket.recv(Client.RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.tcp_socket.close()
                sys.exit(1)

            print("Received: ", recvd_bytes.decode(self.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_udp_socket(self):
        try:
            #UDP
            # Service discovery done using UDP packets.
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Arrange to send a broadcast service discovery packet.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Set the socket for a socket.timeout if a scanning recv
            # fails.
            self.udp_socket.settimeout(Client.SCAN_TIMEOUT);
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def get_tcp_socket(self):
        try:
            #TCP
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow us to bind to the same port right away.            
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as msg:
            print(msg)
            sys.exit(1)




    def scan_for_service(self):
        # Collect our scan results in a list.
        scan_results = []

        # Repeat the scan procedure a preset number of times.
        for i in range(Client.SCAN_CYCLES):

            # Send a service discovery broadcast.
            print("Sending broadcast scan {}".format(i))            
            self.udp_socket.sendto(Client.SCAN_CMD_ENCODED, Client.SERVICE_DISCOVERY_ADDRESS_PORT)
        
            while True:
                # Listen for service responses. So long as we keep
                # receiving responses, keep going. Timeout if none are
                # received and terminate the listening for this scan
                # cycle.
                try:
                    recvd_bytes, address = self.udp_socket.recvfrom(Client.RECV_SIZE)
                    recvd_msg = recvd_bytes.decode(Client.MSG_ENCODING)

                    # Record only unique services that are found.
                    if (recvd_msg, address) not in scan_results:
                        scan_results.append((recvd_msg, address))
                        continue
                # If we timeout listening for a new response, we are
                # finished.
                except socket.timeout:
                    break

        # Output all of our scan results, if any.
        if scan_results:
            for result in scan_results:
                print(result)
        else:
            print("No services found.")
            
                
########################################################################
# Fire up a client/server with -r if run directly.
########################################################################


if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






