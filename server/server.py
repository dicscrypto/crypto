#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
from os import getcwd, path, system
from threading import Thread    # for handling task in separate jobs we need threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import datetime         # for composing date/time stamp
import sys              # handle system error
import socket           # tcp protocol
import time             # for delay purpose
import hashlib
import traceback        # for print_exc function

class Connection_Server:
    def __init__(self):
        self.host = socket.gethostname() 
        self.port = 4444                

class Data_Server:
    def __init__(self):
        self.default_menu = getcwd() + "\\menu.txt"
        self.menu_file_md5_hexdigest = ""

        self.default_save_base = getcwd() + "\\result-"
        self.default_encrypted_save_base = getcwd() + "\\encrypted-result-"
        self.default_decrypted_save_base = getcwd() + "\\decrypted-result-"

class Command_Server:
    def __init__(self):
        self.GET_MENU = "GET_MENU"
        self.GET_MENU_HASH = "GET_MENU_HASH"
        
        self.GET_SERVER_PUBLIC_KEY_FILE = "GET_SERVER_PUBLIC_KEY_FILE"
        self.GET_SERVER_PUBLIC_KEY_FILE_HASH = "GET_SERVER_PUBLIC_KEY_FILE_HASH"

        self.SEND_CLIENT_PUBLIC_KEY_FILE = "SEND_CLIENT_PUBLIC_KEY_FILE"
        self.SEND_CLIENT_PUBLIC_KEY_HASH = "SEND_CLIENT_PUBLIC_KEY_HASH"

        self.END_DAY = "CLOSING"

class Encryption_Server:
    def __init__(self):
        self.private_key_file = getcwd() + "\\private.pem"
        self.public_key_file = getcwd() + "\\receiver.pem"
        self.public_key_file_md5_hexdigest = ""

        self.client_public_key_file = getcwd() + "\\client_public_key.pem"
        self.uploaded_client_public_key_md5_hexdigest = ""

        self.stored_client_public_key_file_md5_hexdigest = ""

    def generate_private_and_public_key(self):
        key = RSA.generate(2048)
        private_key = key.export_key()

        with open(self.private_key_file, "wb") as private_key_file:
            private_key_file.write(private_key)

        public_key = key.publickey().export_key()

        with open(self.public_key_file, "wb") as public_key_file:
            public_key_file.write(public_key)

    def get_file_hash(self, target_file):
        target_file_exist = path.exists(target_file)

        if target_file_exist:
            my_hash = hashlib.new("md5")

            with open(target_file, "rb") as tgt_file:
                while True:
                    read_bytes = tgt_file.read(4096)

                    if read_bytes == b'':
                        break

                    my_hash.update(read_bytes)
                    target_file_md5_hexdigest = my_hash.hexdigest()
                
                del my_hash
            
            return target_file_md5_hexdigest

        else:
            print(f"[!] File not found : {self.public_key_file}")
            sys.exit(1)

    def decrypt_file(self, file_to_be_decrypted, decrypted_file):
        with open(file_to_be_decrypted, "rb") as file_to_decrypt:
            private_key = RSA.import_key(open(self.private_key_file).read())
        
            encrypted_session_key, nonce, tag, ciphertext = [file_to_decrypt.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

            # Decrypt the session key with the private RSA key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_session_key = cipher_rsa.decrypt(encrypted_session_key)

            # Decrypt the data with the AES session key
            cipher_aes = AES.new(decrypted_session_key, AES.MODE_EAX, nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

            with open(decrypted_file, "wb") as decrypted_file_to_be_written:
                decrypted_file_to_be_written.write(plaintext)

def pause():
    print()
    system("pause")

def short_pause():
    time.sleep(1.5)

def clear_screen():
    system("cls")

def send_file(conn, file_to_be_sent, MAX_BUFFER_SIZE):
    file_to_be_sent_exists = path.exists(file_to_be_sent)

    if file_to_be_sent_exists:
        with open(file_to_be_sent, "rb") as file_to_send:
            while True:
                read_bytes = file_to_send.read(MAX_BUFFER_SIZE)

                if read_bytes == b'': break

                conn.send(read_bytes)
    
    else:
        print(f"[!] File not found : {file_to_be_sent}")
        sys.exit(1)

def download_file(conn, file_to_be_downloaded, MAX_BUFFER_SIZE):
    while True:
        data_from_client = conn.recv(MAX_BUFFER_SIZE)

        if data_from_client == b'': break

        with open(file_to_be_downloaded, "wb") as downloaded_file:
            downloaded_file.write(data_from_client)

def process_connection(conn, ip_addr, MAX_BUFFER_SIZE):  
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
   
    while net_bytes != b'':
        user_command = net_bytes.decode("utf8").rstrip()

        if user_command == command_from_client.GET_MENU: 
            server_data.menu_file_md5_hexdigest = server_encryption.get_file_hash(server_data.default_menu)
            
            send_file(conn, server_data.default_menu, MAX_BUFFER_SIZE)

            print("<< Completed: SENDING default menu >>") 
            return

        elif user_command == command_from_client.GET_MENU_HASH:
            conn.send(server_data.menu_file_md5_hexdigest.encode())

            print("<< Completed: SENDING hash of server's default menu >>") 
            return

        elif user_command == command_from_client.GET_SERVER_PUBLIC_KEY_FILE:
            send_file(conn, server_encryption.public_key_file, MAX_BUFFER_SIZE)

            print("<< Completed: SENDING server's public key file >>")
            return
                        
        elif user_command == command_from_client.GET_SERVER_PUBLIC_KEY_FILE_HASH:
            server_encryption.public_key_file_md5_hexdigest = server_encryption.get_file_hash(server_encryption.public_key_file)

            conn.send(server_encryption.public_key_file_md5_hexdigest.encode())

            print("<< Completed: SENDING hash of server's public key file >>") 
            return

        elif user_command == command_from_client.SEND_CLIENT_PUBLIC_KEY_FILE:
            download_file(conn, server_encryption.client_public_key_file, MAX_BUFFER_SIZE)

            print("<< Completed: Downloading client's public key file >>")
            return

        elif user_command == command_from_client.END_DAY: 
            encrypted_filename = server_data.default_encrypted_save_base + ip_addr + " - " + get_formatted_date_and_time() + ".bin"                      
            download_file(conn, encrypted_filename, MAX_BUFFER_SIZE)
            
            print(f"[+] Saving encrypted result file [ {encrypted_filename} ]")

            decrypted_filename = server_data.default_decrypted_save_base + ip_addr + " - " + get_formatted_date_and_time() + ".txt"
            server_encryption.decrypt_file(encrypted_filename, decrypted_filename)

            print(f"[+] Saving decrypted result file : [ {decrypted_filename} ]")
            print("<< Completed: CLOSING done >>") 
            return

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection(conn, ip, MAX_BUFFER_SIZE)
    conn.close()  
   
    print(f'[-] Connection Terminated -> {ip} : {port}')
    return

def start_server():   
    clear_screen()

    # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
        # This is for easy starting/killing the app
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print('[+] Socket created.')
        
        try:
            my_socket.bind((local_connection.host, local_connection.port))
            print('[+] Socket bind complete.')
    
        except socket.error as error:     
            print(f'[!] Bind failed : {str(sys.exc_info())}')
            print(error.with_traceback())

            sys.exit(1)

        #Start listening on socket and can accept 10 connection
        my_socket.listen()
        print('[+] Socket now listening.')

        # this will make an infinite loop needed for 
        # not reseting server for every client
        try:
            while True:
                conn, addr = my_socket.accept()
                
                # assign ip and port
                ip, port = str(addr[0]), str(addr[1])
                print(f'[+] Connection Accepted -> {ip} : {port}')
                
                try: Thread(target = client_thread, args = (conn, ip, port)).start()
                
                except Exception as error:
                    print(f"[!] Threading error : {error}")
                    traceback.print_exc()

        except: pass
        
        return

def get_formatted_date_and_time():
    now = datetime.datetime.now()
    formatted_date_and_time = now.strftime("%Y-%m-%d_%H%M")

    return(formatted_date_and_time)

local_connection = Connection_Server()
server_data = Data_Server()
command_from_client = Command_Server()
server_encryption = Encryption_Server()


start_server()  