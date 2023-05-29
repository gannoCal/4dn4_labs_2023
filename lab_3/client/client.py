
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
                print("(recv: {})".format(recvd_bytes))

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
        except Exception as e:
            print(e)



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
            self.recieve_8b_delim_message(self.process_get_callback)
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
# Fire up a client if run directly.
########################################################################

if __name__ == '__main__':
    Client()

########################################################################






