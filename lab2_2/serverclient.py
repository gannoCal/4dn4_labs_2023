#!/usr/bin/python3

#COMP ENG 4DN4 Advanced Internet Communications
#Lab 2 
#Caleb Gannon, 400137271, gannonc 
#Jack Wawrychuk, 400145293, wawrychj
#Sophie Ciardullo, 400114490, ciards1
#Zachary Thorne, 400139761, thornez
#March 12th, 2023

#Run server by doing python serverclient.py -r server
#Run client by doing python serverclient.py -r client

import socket
import argparse
import sys
from cryptography.fernet import Fernet

#******************************************
#**************Server Class****************
#******************************************
class Server:
    #Set server Parameters
    HOSTNAME = "0.0.0.0"      
    PORT = 50000
    RECV_BUFFER_SIZE = 1024 
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8" #enable a larger charset
    SOCKET_ADDRESS = (HOSTNAME, PORT)
    CSV_FILE = "./course_grades_2023.csv"

    #Set up a map for the CSV headers
    csv_dict = {}
    csv_header_map = {
            "Name" : 0,
            "ID Number" : 1,
            "Key" : 2,
            "Lab 1" : 3,
            "Lab 2" : 4,
            "Lab 3" : 5,
            "Lab 4" : 6,
            "Midterm" : 7,
            "Exam 1" : 8,
            "Exam 2" : 9,
            "Exam 3" : 10,
            "Exam 4" : 11

            }
    inverse_csv_map = dict((x, y) for y, x in csv_header_map.items())

    user_found = False

    #Init function
    def __init__(self):
        self.read_csv_file()
        self.create_listen_socket()
        self.process_connections_forever()


    #Function for reading csv file
    def read_csv_file(self):
        #Open up file
        f = open(Server.CSV_FILE, 'r')
        firstline = 1
        print("Data read from CSV file: ")
        for line in f.readlines():
            print(line)
            if firstline:
                for header in line.split(','):
                    self.csv_dict[header.strip()] = []
            else:
                for i,entry in enumerate(line.split(',')):
                    self.csv_dict[self.inverse_csv_map[i]].append(entry.strip())
            firstline = 0
        #print(self.csv_dict)
        f.close()

    #Create TCP over IPv4 Socket
    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Create the socket
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Set optiosn so it can be reused 
            self.socket.bind(Server.SOCKET_ADDRESS) #Bind it to the socket address
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG) #Set to listen mode
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    #Loop which runs forever and checks for connection requests
    def process_connections_forever(self):
        try:
            while True:
                self.connection_handler(self.socket.accept()) #Enter connection_handler function once accept returns values 
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    #Returns 3 strings to main handler
    def split_command(self, recvd_str):
        command_bytes   = recvd_str.encode(Server.MSG_ENCODING)[7:]
        id_bytes        = recvd_str.encode(Server.MSG_ENCODING)[:7]
        id_str = id_bytes.decode(Server.MSG_ENCODING)
        welcome_bytes = b""

        #Loop through csv dictionary item to see if student number exists if it does, populates welcome bytes with their info
        if id_str in self.csv_dict["ID Number"]:
            welcome_bytes = (("Hello "+self.csv_dict["Name"][self.csv_dict["ID Number"].index(id_str)]+"!").encode(Server.MSG_ENCODING))
            self.user_found = True
            self.student_idx = self.csv_dict["ID Number"].index(id_bytes.decode(Server.MSG_ENCODING))
            print("User found.")
        #If the student number doesnt exist, populate welcome bytes with a failure message
        else:
            welcome_bytes = (f"Failed to find user with ID {id_str}.".encode(Server.MSG_ENCODING))
            print("User not found.")
        
        return (id_bytes, command_bytes, welcome_bytes)

    #FUnction that will calculate the averages of a grade in the CSV 
    def get_avg_from_str(self, s):
        avg = 0
        for grade in self.csv_dict[s]:
            avg += int(grade)
        avg /= len(self.csv_dict[s])
        return float(avg)

    #Functions that handles the connection onces its established
    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))
        print(client)

        while True:
            try:
                #print(connection)
                #Recieve bytes and close connections if nothing is recieved
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                #Decode the message
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                
                print("Received: ", recvd_str)

                self.user_found = False
                
                #Enter split function which will split up the recieved messages into 3 different strings: the student number, command, and welcome bytes 
                (id_bytes, command_bytes, welcome_bytes) = self.split_command(recvd_str)
                sent_str = ""
                response_bytes = b""
                delimiter_bytes = b"Response:"

                #Reply with welcome bytes saying its a failure if the student number does not exist
                if not self.user_found:
                    sent_bytes = welcome_bytes 
                    connection.sendall(sent_bytes) #Send all welcome bytes back to client
                    sent_str = sent_bytes.decode(Server.MSG_ENCODING)
                    print("Closing client connection ... ")
                    #Close the connection - if client hasn't already
                    try:
                        connection.close()
                    except Exception as e:
                        print("Connection was already closed")
                    finally:
                        break

                #If user has been auththenticated, process command
                else:
                    print(f"Received {command_bytes.decode(Server.MSG_ENCODING)} command from client.")
                    #Case statement in order to get right command depending on the command
                    match command_bytes.decode(Server.MSG_ENCODING):
                        case "GMA":
                            type_ = "Midterm"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL1A":
                            type_ = "Lab 1"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL2A":
                            type_ = "Lab 2"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL3A":
                            type_ = "Lab 3"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL4A":
                            type_ = "Lab 4"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GEA":
                            type_ = "Exam"
                            avg = self.get_avg_from_str(type_ + " 1") + self.get_avg_from_str(type_ + " 2") + self.get_avg_from_str(type_ + " 3") + self.get_avg_from_str(type_ + " 4")
                            avg /= 4
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GG":
                            non_grade_data = ["Name", "ID Number", "Key"]
                            grades_str = ""
                            for key in self.csv_dict.keys():
                                if not key in non_grade_data:
                                    grade = self.csv_dict[key][self.student_idx]
                                    grades_str += f"\t{key}: {grade}\n"
                            response_bytes = f"Grades Found:\n{grades_str}".encode(Server.MSG_ENCODING)

                        case _:
                            response_bytes = b"Invalid Command!"

                    #Once data collected from case statement, combine with welcome bytes
                    sent_bytes = welcome_bytes + delimiter_bytes + response_bytes
                    
                    #Encrypt the message and then send the bytes back to the client
                    fernet = Fernet(self.csv_dict["Key"][self.student_idx].encode('utf-8'))
                    connection.sendall(fernet.encrypt(sent_bytes))
                    sent_str = sent_bytes.decode(Server.MSG_ENCODING)
                print("Sent: ", sent_str)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

#******************************************
#**************Client Class****************
#******************************************
class Client:
    #Params
    #SERVER_HOSTNAME = "10.0.2.15"    
    SERVER_HOSTNAME = socket.gethostbyname(socket.gethostname()) #Get ip address of current machine
    RECV_BUFFER_SIZE = 1024

    STUDENT_ID = ""
    SECRET_KEY = ""
    
    #Class vars
    recieved_str = "" 

    def __init__(self):
        self.get_student_id_and_key()
        #self.send_console_input_forever()
        self.send_and_confirm_student_id()

    #Ask user to input desired student ID 
    def get_student_id_and_key(self):
        self.STUDENT_ID = ""
        self.SECRET_KEY = ""

        #Input Student Number
        while(self.STUDENT_ID == ""):
            self.STUDENT_ID = input("Enter your student id:\n")
        #Input secret key
        while(self.SECRET_KEY == ""):
            self.SECRET_KEY = input("Enter your secret key:\n")
        # error handling
        try:
            self.fernet = Fernet(self.SECRET_KEY.encode('utf-8'))
        except:
            print("Invalid key was entered. Please restart client application and try again.")
            sys.exit(1)

    #Get user to input the command 
    def get_command(self):
        valid_command = False
        #Loops until vaild command is entered
        while(not valid_command):
            self.input_text = input("Enter a command:\n")
            print("Command entered: " + self.input_text)
            valid_command = True
            #Take user input and see if it matches any of the following commands
            match self.input_text:
                case "GMA":
                    type_ = "Midterm"
                    print(f"Fetching {type_} average")
                case "GL1A":
                    type_ = "Lab 1"
                    print(f"Fetching {type_} average")
                case "GL2A":
                    type_ = "Lab 2"
                    print(f"Fetching {type_} average")
                case "GL3A":
                    type_ = "Lab 3"
                    print(f"Fetching {type_} average")
                case "GL4A":
                    type_ = "Lab 4"
                    print(f"Fetching {type_} average")
                case "GEA":
                    type_ = "Exam"
                    print(f"Fetching {type_} average")
                case "GG":
                    print("Getting Grades")
                case _:
                    print("Invalid Command. Try Again.")
                    valid_command = False

    #Create the socket
    def get_socket(self):
        try:
            #Create a TCP over IPv4 socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
        except Exception as msg:
            print(msg)
            sys.exit(1)

    #Connect client socket to server socket
    def connect_to_server(self):
        try:
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT)) #Connect the client to the server
            print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    #def get_console_input(self):
    #    while True:
    #        self.input_text = input("Input: ")
    #        if self.input_text != "":
    #            break
    
    #def send_console_input_forever(self):
    #    while True:
    #        try:
    #            self.get_console_input()
    #            self.connection_send()
    #            self.connection_receive()
    #        except (KeyboardInterrupt, EOFError):
    #            print()
    #            print("Closing server connection ...")
    #            self.socket.close()
    #            sys.exit(1)

    #Main loop trying to connect and send data to server
    def send_and_confirm_student_id(self):
        try:
            while(True):
                self.get_command()
                #Reconnect to server
                self.get_socket()
                self.connect_to_server()
                #Send the message + check response
                self.connection_send()
                self.connection_receive()
                #Close connection
                print("Closing server connection ...")
                self.socket.close()
                #get next ID + Key
                self.get_student_id_and_key()

        except (KeyboardInterrupt, EOFError):
            print()
            print("Closing server connection ...")
            self.socket.close()
            sys.exit(1)
                
    #Send Student id, secret key and command to server
    def connection_send(self):
        try:
            self.socket.sendall((self.STUDENT_ID+self.input_text).encode(Server.MSG_ENCODING)) #Encode and send all data 
        except Exception as msg:
            print(msg)
            sys.exit(1)

    #Recieve data from server 
    def connection_receive(self):
        try:
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)#recieve bytes 
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)
            
            
            #Decrypt the message
            #Only if it is not an error message - which will not be encrypted
            if recvd_bytes.decode(Server.MSG_ENCODING).find("Failed to find user with ID") == -1:
                try:
                    decoded_bytes = self.fernet.decrypt(recvd_bytes)
                except Exception as e:
                    decoded_bytes = recvd_bytes
                    print("Failed to decode message! (Invalid key?)")
            else:
                decoded_bytes = recvd_bytes

            recieved_str = decoded_bytes.decode(Server.MSG_ENCODING)
            messages = recieved_str.split("Response:")
            for message in messages:
                if messages.index(message) == 0:
                    print("Message: ", message)
                else:
                    print("Data: ", message)

        except Exception as msg:
            print(msg)
            sys.exit(1)

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()
