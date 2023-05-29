
#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import datetime
import os
import netifaces as ni
import json
import base64
import threading

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
    buffer              = b''
    data                = None
    exception           = None
    response            = None
    def __init__(self, client):
        self.client = client
    
    def reset(self):
        self.buffer              = b''
        self.data                = None
        self.exception           = None
        self.response            = None

class Server:

    ALL_IF_ADDRESS = "0.0.0.0"
    CRDS_DISCOVERY_PORT = 30000
    CRDS_ADDRESS = (ALL_IF_ADDRESS, CRDS_DISCOVERY_PORT)
    PRINT_RECV_FILE_STREAM = False

    MSG_ENCODING = "utf-8" # Unicode text encoding.

    BACKLOG = 5

    RECV_SIZE_TCP = 10

    chatrooms = []

    EOM_DELIM = b"\0"

    

    def __init__(self):
        self.print_initial_output()
        self.create_socket()
        self.receive_forever()

    def display_files(self):
        dir_str = ""
        for root, dirs, files in os.walk("."):
            for filename in files:
                dir_str += os.path.join(root, filename) + '\n'
        print(dir_str)

    def print_initial_output(self):
        pass

    def create_socket(self):
        try:
            ##TCP
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.tcp_socket.bind( Server.CRDS_ADDRESS )

            ############################################################
            # Set the (listen) socket to non-blocking mode.
            self.tcp_socket.setblocking(False)
            ############################################################            

            # Set socket to listen state.
            self.tcp_socket.listen(Server.BACKLOG)
            print("CRDS Service Listening on port {} ...".format(Server.CRDS_ADDRESS))
            print(72*"*")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        # Keep a list of the current client connections.
        self.connected_clients = []
        
        while True:
            try:
                ##TCP Handler
                self.check_for_new_connections()
                self.service_connected_clients()
                
                


            except KeyboardInterrupt:
                print("\nClosing client connections...")
                current_client_list = self.connected_clients.copy()
                for client in current_client_list:
                    connection, address_port = client.client
                    try:
                        connection.close()
                    except Exception as msg:
                        print(msg)
                print("Exiting.")
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

                if b"\0" in recvd_bytes:
                    client.data = json.loads(base64.b64decode(client.buffer + recvd_bytes[:recvd_bytes.find(b"\0")]).decode(Server.MSG_ENCODING))
                    if client.data["cmd"] != "ping":
                        print("Recieved:", client.data)
                        print("From:", address_port)
                    self.service_client_request(client)
                    self.send_server_response(client)

                    client.reset()
                    client.buffer += recvd_bytes[recvd_bytes.find(b"\0")+1:] #carry over extra data
                else:
                    client.buffer += recvd_bytes
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass

    def service_client_request(self, client):
        data = client.data
        if data["cmd"] == "makeroom":
            names       = [x["room_name"] for x in self.chatrooms]
            addresses   = [x["address"] for x in self.chatrooms]
            ports       = [x["port"] for x in self.chatrooms]

            

            if not self.valid_address(data["address"]):
                client.exception = "Invalid IPv4 Address!"
            elif not self.valid_port(data["port"]):
                client.exception = "Invalid Port!"
            elif not self.valid_multicast_address(data["address"]):
                client.exception = "Invalid Multicast Address!"
            elif data["room_name"] in names:
                client.exception = "Duplicate Room Name!"
            elif self.port_address_in_use(data):
                    client.exception = "Address and Port already in use!"
            else:
                room = dict(data)
                del room["cmd"]
                self.chatrooms.append(room)
                print(72*"*")
                print("Chatrooms Updated!")
                print(self.chatrooms)
                print(72*"*")

        if data["cmd"] == "getdir":
            if len(self.chatrooms) == 0:
                client.exception = "No chat rooms exist!"
            else:
                client.response = self.chatrooms

        if data["cmd"] == "deleteroom":
            for x in self.chatrooms:
                if x["room_name"] == data["room_name"]:
                    self.chatrooms.remove(x)

        if data["cmd"] == "chat":
            for x in self.chatrooms:
                if x["room_name"] == data["room_name"]:
                    client.response = x

            if not client.response:
                client.exception = "Room not found!!"

        if data["cmd"] == "ping":
            client.response = "alive"




        if not client.exception is None:
                print(client.exception)
    

    def port_address_in_use(self, data):
        ports_on_addr = [x["port"] for x in self.chatrooms if x["address"] == data["address"]]
        if data["port"] in ports_on_addr:
            return True
        return False

    def valid_address(self, addr):
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False
    
    def valid_port(self, port):
        if int(port) < 1 or int(port) > 65535:
            return False
        return True
    
    def valid_multicast_address(self, addr):
        addr_vals = addr.split('.')
        if int(addr_vals[0]) > 239 or int(addr_vals[0]) < 224 or len(addr_vals) != 4:
            return False
        return True

    def send_server_response(self, client):
        connection, address_port = client.client
        data = {}
        if client.exception is None:
            data["status"]      = "400"
            data["response"]    = ''
            if client.response:
                data["response"]    = client.response
        else:
            data["status"] = "401"
            data["exception"] = client.exception

        ##send response to client
        connection.sendall(base64.b64encode(json.dumps(data).encode(Server.MSG_ENCODING))+self.EOM_DELIM)

    

    



########################################################################
# Service Discovery Client
########################################################################

class Client:

    RECV_SIZE = 1024
    MSG_ENCODING = "utf-8"    

    CRDS_ADDRESS = ni.ifaddresses('lo')[ni.AF_INET][0]['addr']
        
    SERVICE_PORT = 30000
    SERVICE_ADDRESS = (CRDS_ADDRESS, SERVICE_PORT)

    RECV_BUFFER_SIZE = 8 # Used for recv from server.
    RECV_BUFFER_SIZE_CHAT = 240 # Used for recv from multicast.
    MSG_ENCODING = "utf-8" # Unicode text encoding.

    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)

    CMD = {
        "makeroom" : b'\x01',
        "getdir" : b'\x02',
        "deleteroom" : b'\x03',
        }


    local_chatrooms = []

    chat_history = []

    TTL = 1 # multicast hop count
    TTL_BYTE = TTL.to_bytes(1, byteorder='big')


    EOM_DELIM = b"\0"
    

    def __init__(self):
        self.connected = False
        self.quiet_connected = False
        self.user_name = None
        self.user_input = ""
        self.chat_active = False
        self.input_recieved = False
        self.input_capture_lock = threading.Lock()
        try:
            while(1):
                self.start_prompt()
        except Exception as msg:
            print(msg)
            sys.exit(1)
        


    def remove_empty_entries(self, str_arr):
        return [str_ for str_ in str_arr if (str_ != '')]

    def start_prompt(self):
        try:
            valid_command = False
            while(not valid_command):
                input_msg = ""
                if not self.chat_active:
                    input_msg = "Enter a command:\n"
                self.input_text = input(input_msg)
                
                if(self.chat_active):
                    self.input_capture_lock.release()
                    continue
                print("Command entered: " + self.input_text)
                valid_command = True
                if(self.input_text == "connect"):
                    if not self.check_connected_to_CRDS(print_error = False):
                        self.connect_to_CRDS()
                    else:
                        print("Already connected to CRDS")
                elif(self.input_text[0:5] == "name "):
                    input_arr = self.remove_empty_entries(self.input_text.split(" "))
                    if(len(input_arr) != 2):
                        print("Invalid name command: name <chat name>")
                        valid_command = False
                        continue
                    self.user_name = input_arr[1]
                    print("Username changed to:", self.user_name)
                elif(self.input_text[0:5] == "chat "):
                    if not self.check_connected_to_CRDS(print_error = False):
                        self.connect_to_CRDS(True)
                    input_arr = self.remove_empty_entries(self.input_text.split(" "))
                    if(len(input_arr) != 2):
                        print("Invalid chat command: chat <chat room name>")
                        valid_command = False
                        continue
                    if self.user_name is None:
                        print("Must set name! name <chat name>")
                        continue
                    self.active_chat = input_arr[1]
                    self.start_chat_mode()
                elif(self.input_text == "bye"):
                    if not self.check_connected_to_CRDS():
                        continue
                    print(72*"*")
                    print("Closing server connection ... ")
                    self.tcp_socket.close()
                    self.connected = False
                elif(self.input_text == "getdir"):
                    if not self.check_connected_to_CRDS():
                        continue
                    self.getdir()
                elif(self.input_text[0:9] == "makeroom "):
                    if not self.check_connected_to_CRDS():
                        continue
                    input_arr = self.remove_empty_entries(self.input_text.split(" "))
                    if(len(input_arr) != 4):
                        print("Invalid makeroom command: makeroom <chat room name> <address> <port> ")
                        valid_command = False
                        continue
                    self.room_details = input_arr[1:]
                    self.make_room()
                elif(self.input_text[0:11] == "deleteroom "):
                    if not self.check_connected_to_CRDS():
                        continue
                    input_arr = self.remove_empty_entries(self.input_text.split(" "))
                    if(len(input_arr) != 2):
                        print("Invalid deleteroom command: deleteroom <chat room name>")
                        valid_command = False
                        continue
                    self.room_details = input_arr[1:]
                    self.delete_room()
                else:
                    print("Invalid Command. Try Again.")
                    valid_command = False
                
        except KeyboardInterrupt as msg:
            if self.chat_active:
                self.chat_active = False
                self.chat_history = []
                print()
                if(self.input_capture_lock.locked()):
                    self.input_capture_lock.release()

                self.send.join()
                self.recv.join()

                self.send_socket.sendto(("{}: ".format(self.user_name)+"<left the chat>").encode(Server.MSG_ENCODING), self.chat_address_tuple)

                self.recv_socket.close()
                self.send_socket.close()

                del self.input_capture_lock
                self.input_capture_lock = threading.Lock()

            else:
                print(msg)
                sys.exit(1)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def check_connected_to_CRDS(self, print_error = True):
        if not self.connected:
            if print_error:
                print("Error: Not connected to CRDS")
            return False
        else:
            if not self.ping_CRDS():
                return False
        return True

    def quiet_disconnect_from_CRDS(self):
        self.tcp_socket.close()
        self.connected = False

    def ping_CRDS(self):
        data = {}
        data["cmd"]         = "ping"
        self.send_payload(data)
        
        status, data = self.process_server_reponse(disable_print=True)
        return status

    def connect_to_CRDS(self, quiet=False):
        self.quiet_connected = quiet
        self.get_socket()
        self.connected = self.connect_to_service()
        

    def start_chat_mode(self):
        if self.get_chatroom_address():
            self.input_capture_lock.acquire()
            self.setup_multicast_sockets()
            self.start_messaging_service()

    def start_messaging_service(self):
        self.send = threading.Thread(target=self.send_multicast_messages, args=())
        self.recv = threading.Thread(target=self.recieve_multicast_messages, args=())

        self.chat_active = True

        self.recv.daemon = True
        self.send.daemon = True

        try:
            self.send.start()
            self.recv.start()
        except KeyboardInterrupt as msg:
            self.chat_active = False




    def send_multicast_messages(self):
        ##send welcome message
        self.send_socket.sendto(("{}: ".format(self.user_name)+"<joined the chat>").encode(Server.MSG_ENCODING), self.chat_address_tuple)
        
        while self.chat_active:   
            success = self.input_capture_lock.acquire()
            user_input = self.input_text
            if not self.chat_active:
                self.user_input = user_input
                break

            self.send_socket.sendto(("{}: ".format(self.user_name)+user_input).encode(Server.MSG_ENCODING), self.chat_address_tuple)

    def recieve_multicast_messages(self):
        while self.chat_active:
            try:
                data, address_port = self.recv_socket.recvfrom(self.RECV_BUFFER_SIZE_CHAT)
            except socket.timeout:
                #do nothing, continue to monitor for data
                continue
                
            address, port = address_port
            self.chat_history.append("{}".format(data.decode(Server.MSG_ENCODING)))
            
            print("\n"+72*"*")
            print("CHAT HISTORY:")
            for msg in self.chat_history:
                print(msg)
            print(72*"*")
            print("Type a message and press Enter to chat:")
        

    def get_chatroom_address(self):
        data = {}
        data["cmd"]         = "chat"
        data["room_name"]   = self.active_chat
        response = None
        status = True
        if self.connected:
            ##get latest server data
            self.send_payload(data)

            status, server_data = self.process_server_reponse()
            if status:
                response = server_data["response"]
        else:
            #used cached addresses
            for x in self.local_chatrooms:
                if x["room_name"] == data["room_name"]:
                    response = x
            if response is None:
                print("Chatroom is not found! (server down - local cache was checked)")
                status = False
                return status
        
        if status:
            print("Chatting on ({}, {})".format(response["address"], response["port"]))
            self.chat_address_tuple = (response["address"], int(response["port"]))

        if self.quiet_connected:
            self.quiet_disconnect_from_CRDS()


        return status



    def setup_multicast_sockets(self):
        self.create_send_socket()
        self.create_recv_socket()

    def create_send_socket(self):
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Set the TTL for multicast.
        self.send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.TTL_BYTE)

        # Bind to the interface that will carry the multicast 
        self.send_socket.bind((self.CRDS_ADDRESS, 0)) # Have the system pick a port number.

    def create_recv_socket(self):
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        ##note - unclear about whether we mainatin a local listing of the chat addresses, or if we have to be connected to the server

        self.recv_socket.settimeout(0.1) ##check for message every 100ms

        self.recv_socket.bind(self.chat_address_tuple)
        multicast_group_bytes = socket.inet_aton(self.chat_address_tuple[0])
        # Set up the interface to be used.
        multicast_iface_bytes = socket.inet_aton(self.CRDS_ADDRESS)

        # Form the multicast request.
        multicast_request = multicast_group_bytes + multicast_iface_bytes

        self.recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

    
    def getdir(self):
        data = {}
        data["cmd"]         = "getdir"
        self.send_payload(data)
        
        status, server_data = self.process_server_reponse(print_response=False)
        if status:
            response = server_data["response"]
            self.local_chatrooms = response

            output_str = ""
            output_str = 72*"*" + "\n"
            for room in self.local_chatrooms:
                output_str += json.dumps(room) + "\n"
            output_str += 72*"*"

            print(output_str)
        
    def make_room(self):
        data = {}
        data["cmd"]         = "makeroom"
        data["room_name"]   = self.room_details[0]
        data["address"]     = self.room_details[1]
        data["port"]        = self.room_details[2]
        self.send_payload(data)

        self.process_server_reponse()

    def delete_room(self):
        data = {}
        data["cmd"]         = "deleteroom"
        data["room_name"]   = self.room_details[0]
        self.send_payload(data)

        self.process_server_reponse()

    def send_payload(self, data):
        self.tcp_socket.sendall(base64.b64encode(json.dumps(data).encode(Server.MSG_ENCODING))+self.EOM_DELIM)
        

    def process_server_reponse(self, print_response = True, disable_print = False):
        response = b''
        ##wait for server response
        while not b"\0" in response:
            #set a timeout
            response += self.tcp_socket.recv(self.RECV_BUFFER_SIZE)
            if(len(response) == 0):
                break
        
        if len(response) == 0:
            #connection is closed
            status = False
            data = {}
            print("CRDS is not responding...")
            return status, data

        #interpret server response
        data = json.loads(base64.b64decode(response).decode(Server.MSG_ENCODING))
        status = False
        if int(data["status"]) == 400:
            status = True
            if data["response"] != '' and print_response and not disable_print:
                print(data["response"])
            elif not disable_print:
                print("Command completed successfully!")
        else:
            print("Error Recieved: ", data["exception"])

        return status, data

    def connect_to_service(self):
        try:
            # Connect to the server using its socket address tuple.
            self.tcp_socket.connect(self.SERVICE_ADDRESS)
            print("Connected to \"{}\" on port {}".format(self.SERVICE_ADDRESS[0],self.SERVICE_ADDRESS[1]))
            return True

        except socket.error as msg:
            if self.quiet_connected:
                return False
                pass
                #we will use local cache of chatrooms for "chat" command if server is down
            else:
                print("CRDS is not responding...")
                return False

        except Exception as msg:
            print(msg)
            sys.exit(1)


    


    def get_socket(self):
        try:
            #TCP
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow us to bind to the same port right away.            
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as msg:
            print(msg)
            sys.exit(1)



            
                
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






