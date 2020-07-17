#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
from os import getcwd, path, system
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import datetime
import sys              
import socket
import time
import hashlib

class Connection_Client:
    def __init__(self):
        self.host = socket.gethostname()
        self.port = 4444        

class Data_Client:
    def __init__(self):
        self.menu_file = getcwd() + "\\menu.txt"
        self.menu_file_md5_hexdigest = ""

        self.return_file = getcwd() + "\\day_end.txt"
        self.return_file_md5_hexdigest = ""

        self.encrypted_return_file = getcwd() + "\\day_end.bin"

class Command_Client:
    def __init__(self):
        self.GET_MENU = b"GET_MENU"
        self.GET_MENU_HASH = b"GET_MENU_HASH"

        self.GET_SERVER_PUBLIC_KEY_FILE = b"GET_SERVER_PUBLIC_KEY_FILE"
        self.GET_SERVER_PUBLIC_KEY_FILE_HASH = b"GET_SERVER_PUBLIC_KEY_FILE_HASH"
        
        self.SEND_CLIENT_PUBLIC_KEY_FILE = b"SEND_CLIENT_PUBLIC_KEY_FILE"
        self.SEND_CLIENT_PUBLIC_KEY_HASH = b"SEND_CLIENT_PUBLIC_KEY_HASH"
      
        self.END_DAY = b"CLOSING"

class Encryption_Client:
    def __init__(self):
        self.MAX_BUFFER_SIZE = 4096

        self.private_key_file = getcwd() + "\\private.pem"
        self.public_key_file = getcwd() + "\\receiver.pem"
        self.public_key_file_md5_hexdigest = ""

        self.server_public_key_file = getcwd() + "\\server_public_key_file.pem"
        self.downloaded_server_public_key_file_md5_hexdigest = ""

        self.stored_server_public_key_file_md5_hexdigest = ""

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
                    read_bytes = tgt_file.read(self.MAX_BUFFER_SIZE)

                    if read_bytes == b'': break

                    my_hash.update(read_bytes)
                    target_file_md5_hexdigest = my_hash.hexdigest()
                
                del my_hash
            
            return target_file_md5_hexdigest

        else:
            print(f"[!] File not found : {self.public_key_file}")
            sys.exit(1)

    def download_server_public_key_file(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
            my_socket.connect((connect_to_server.host, connect_to_server.port))
            my_socket.sendall((command_to_server.GET_SERVER_PUBLIC_KEY_FILE))

            data = my_socket.recv(self.MAX_BUFFER_SIZE)

            with open(self.server_public_key_file, "wb") as server_public_key_file:
                server_public_key_file.write(data)
            
    def download_hash_of_public_key_file_from_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
            my_socket.connect((connect_to_server.host, connect_to_server.port))
            my_socket.sendall((command_to_server.GET_SERVER_PUBLIC_KEY_FILE_HASH))

            hash_of_public_key_file_from_server = my_socket.recv(self.MAX_BUFFER_SIZE).decode()
        
        return hash_of_public_key_file_from_server

    def upload_file_to_server(self, file_to_be_uploaded, server_command, MAX_BUFFER_SIZE):
        file_to_be_uploaded_exists = path.exists(file_to_be_uploaded)

        if file_to_be_uploaded_exists:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
                my_socket.connect((connect_to_server.host, connect_to_server.port))
                my_socket.sendall((server_command))

                short_pause()

                with open(file_to_be_uploaded, "rb") as file_to_upload:
                    while True:
                        read_bytes = file_to_upload.read(MAX_BUFFER_SIZE)

                        if read_bytes == b'': break

                        my_socket.send(read_bytes)

        else:
            print(f"[!] File not found : {file_to_be_uploaded}")
            sys.exit(1)

    def upload_client_public_key_to_server(self):
        self.upload_file_to_server(self.public_key_file, command_to_server.SEND_CLIENT_PUBLIC_KEY_FILE, self.MAX_BUFFER_SIZE)

    def upload_client_public_key_hash_to_server(self):
        self.upload_file_to_server(self.public_key_file_md5_hexdigest, command_to_server.SEND_CLIENT_PUBLIC_KEY_HASH, self.MAX_BUFFER_SIZE)

    def encrypt_file(self, file_to_be_encrypted, encrypted_file):
        with open(file_to_be_encrypted, "rb") as file_to_encrypt:
            plaintext = file_to_encrypt.read()

        recipient_key_server = RSA.import_key(open(client_encryption.server_public_key_file).read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key_server)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        with open(encrypted_file, "wb") as encrypted_file_to_be_written:
            for x in (encrypted_session_key, cipher_aes.nonce, tag, ciphertext):
                encrypted_file_to_be_written.write(x)

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

def determine_integrity_of_menu_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
        my_socket.connect((connect_to_server.host, connect_to_server.port))
        my_socket.sendall(command_to_server.GET_MENU_HASH)

        hash_of_menu_file_from_server = my_socket.recv(4096)
        server_menu_md5_hexdigest = hash_of_menu_file_from_server.decode()

    client_data.menu_file_md5_hexdigest = client_encryption.get_file_hash(client_data.menu_file)

    if client_data.menu_file_md5_hexdigest == server_menu_md5_hexdigest: 
        return("hash_check_passed")

    else: 
        return("hash_check_failed")

def get_menu_file_from_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
        my_socket.connect((connect_to_server.host, connect_to_server.port))
        my_socket.sendall(command_to_server.GET_MENU)

        data = my_socket.recv(4096)

        with open(client_data.menu_file, "wb") as menu_file:
            menu_file.write(data)

def download_menu_file_and_check_integrity():
    clear_screen()

    get_menu_file_from_server()
    short_pause()

    return_code = determine_integrity_of_menu_file()

    if return_code == "hash_check_passed":
        with open(client_data.menu_file, 'r') as menu_file: 
            lines = menu_file.readlines()

        print()

        for line in lines: 
            print(line.strip())

    elif return_code == "hash_check_failed":
        print("Hash check failed.")
        print("Please try re-downloading menu again.")

    pause()

def print_header(header_message):
    print("=" * 64)
    print(f"{header_message}")
    print("=" * 64)

def upload_end_of_day_report_to_server():
    client_encryption.download_server_public_key_file()

    client_encryption.stored_server_public_key_file_md5_hexdigest = client_encryption.download_hash_of_public_key_file_from_server()
    client_encryption.downloaded_server_public_key_file_md5_hexdigest = client_encryption.get_file_hash(client_encryption.server_public_key_file)

    if client_encryption.downloaded_server_public_key_file_md5_hexdigest == client_encryption.stored_server_public_key_file_md5_hexdigest:
        client_encryption.encrypt_file(client_data.return_file, client_data.encrypted_return_file)
        client_encryption.upload_file_to_server(client_data.encrypted_return_file, command_to_server.END_DAY, client_encryption.MAX_BUFFER_SIZE)

        print("\nUploading of report completed!")
        pause()

    else:
        print("\nServer's Public Key File has been altered.")
        print("Please do a manual verification.")
        sys.exit(1)

def menu():
    while True:
        clear_screen()
        print_header("Welcome to SPAM.")

        print()
        print("1. Download menu file & Perform intergrity check.")
        print("2. Upload end of day report to server.")

        instructions = "\nOnly digits are accepted."
        instructions += "\nEnter \"0\" to exit."
        instructions += "\n\nOption -> "

        try:
            option = int(input(instructions).strip())

            if option == 0: break

            elif option == 1: download_menu_file_and_check_integrity()

            elif option == 2: upload_end_of_day_report_to_server()

        except KeyboardInterrupt:
            print("\nControl + C detected, Exiting program.")
            short_pause()
            break

        except ValueError:
            print("\nPlease check your input again.")
            short_pause()

connect_to_server = Connection_Client()
client_data = Data_Client()
command_to_server = Command_Client()
client_encryption = Encryption_Client()

menu()