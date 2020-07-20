import datetime
import sys
import socket
import time
import hashlib
import traceback

from os import getcwd, system, path

from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

class Connection:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = port

class Data:
    def __init__(self):
        self.menu_file = getcwd() + "\\menu.txt"
        self.md5_of_menu_file = ""

        self.end_of_day_report_base = getcwd() + "\\day_end"
        self.md5_of_end_of_day_report_file = ""

        self.encrypted_end_of_day_report_file_base = getcwd() + "\\day_end_encrypted"
        self.md5_of_encrypted_end_of_day_report_file = ""

class Command:
    def __init__(self):
        self.download_menu = "download_menu"
        self.download_menu_hash = "download_menu_hash"

        self.download_server_public_key_file = "download_server_public_key_file"
        self.download_server_public_key_file_hash = "download_server_public_key_file_hash"

        self.upload_end_of_day_report = "upload_end_of_day_report"

class Security:
    def __init__(self):
        self.private_key_file = getcwd() + "\\server_private.pem"
        self.public_key_file = getcwd() + "\\server_public.pem"

        self.client_public_key_file = getcwd() + "\\client_public.pem"

        self.md5_of_public_key_file = ""

    def new_keys(self, key_size):
        random_generator = Random.new().read
        key = RSA.generate(key_size, random_generator)

        private_key, public_key = key, key.publickey()
        return private_key, public_key

    def encrypt(self, plaintext, public_key_file):
        public_key = RSA.import_key(open(public_key_file).read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        ciphertext = cipher_rsa.encrypt(plaintext.encode())

        return ciphertext

    def encrypt_file(self, file_to_be_encrypted, destination_file):
        with open(file_to_be_encrypted, "rb") as file_to_encrypt:
            plaintext = file_to_encrypt.read()

        ciphertext = self.encrypt(plaintext, server_side_security.client_public_key_file)

        with open(destination_file, "wb") as dest_file:
            dest_file.write(ciphertext)

    def decrypt(self, ciphertext):
        private_key = RSA.import_key(open(self.private_key_file).read())

        cipher_rsa = PKCS1_OAEP.new(private_key)
        plaintext = cipher_rsa.decrypt(ciphertext)

        return plaintext.decode()

    def decrypt_file(self, file_to_be_decrypted, destination_file):
        with open(file_to_be_decrypted, "rb") as file_to_decrypt:
            ciphertext = file_to_decrypt.read()

        plaintext = self.decrypt(ciphertext)

        with open(destination_file, "w") as dest_file:
            dest_file.write(plaintext)

    def create_private_and_public_key(self):
        private_key, public_key = self.new_keys(2048)

        private_key = private_key.export_key()
        public_key = public_key.export_key()

        with open(self.private_key_file, 'wb') as private_key_file:
            private_key_file.write(private_key)

        print("[+] Done creating Private Key.")

        with open(self.public_key_file, 'wb') as public_key_file:
            public_key_file.write(public_key)

        print("[+] Done creating Public Key.")

    def get_file_hash(self, target_file):
        target_file_exist = path.exists(target_file)

        if target_file_exist:
            new_hash = hashlib.new("md5")

            with open(target_file, "rb") as target_f:
                data = target_f.read()
                new_hash.update(data)
                target_file_hexdigest = new_hash.hexdigest()
                del new_hash

            return target_file_hexdigest
        
        else:
            print(f"[!] File not found: {target_file}")

def pause():
    print()
    system("pause")

def short_pause():
    time.sleep(1.5)

def clear_screen():
    system("cls")

def get_formatted_date_and_time():
    now = datetime.datetime.now()
    formatted_date_and_time = now.strftime("%Y-%m-%d_%H%M")

    return(formatted_date_and_time)

def send_file(connection, file_to_be_sent):
    file_to_be_sent_exists = path.exists(file_to_be_sent)

    if file_to_be_sent_exists:
        with open(file_to_be_sent, "rb") as file_to_send:
            data = file_to_send.read()

        connection.sendall(data)

    else:
        print(f"[!] File not found: {file_to_be_sent}")
        sys.exit(1)

def download_file(connection, destination_file):
    data = connection.recv(4096)

    with open(destination_file, "wb") as dest_file:
        dest_file.write(data)

def process_connection(connection, ip_address):
    user_command = connection.recv(4096).decode()

    if user_command == command_from_client.download_menu:
        send_file(connection, server_data.menu_file)

        print("<< Completed: [Sending] default menu. >>")
        return

    elif user_command == command_from_client.download_menu_hash:
        server_data.md5_of_menu_file = server_side_security.get_file_hash(server_data.menu_file)
        connection.sendall(server_data.md5_of_menu_file.encode())

        print("<< Completed: [Sending] default menu hash. >>")
        return

    elif user_command == command_from_client.download_server_public_key_file:
        send_file(connection, server_side_security.public_key_file)

        print("<< Completed: [Sending] public key file. >>")
        return

    elif user_command == command_from_client.download_server_public_key_file_hash:
        server_side_security.md5_of_public_key_file = server_side_security.get_file_hash(server_side_security.public_key_file)
        connection.sendall(server_side_security.md5_of_public_key_file.encode())

        print("<< Completed: [Sending] public key file hash. >>")
        return
    
    elif user_command == command_from_client.upload_end_of_day_report:
        encrypted_end_of_day_report_filename = server_data.encrypted_end_of_day_report_file_base + ip_address + " - " + get_formatted_date_and_time() + ".bin"
        download_file(connection, encrypted_end_of_day_report_filename)
        print(f"[+] Saving encrypted end of day report as: {encrypted_end_of_day_report_filename}")

        decrypted_filename = server_data.end_of_day_report_base + ip_address + " - " + get_formatted_date_and_time() + ".txt"
        server_side_security.decrypt_file(encrypted_end_of_day_report_filename, decrypted_filename)
        print(f"[+] Decrypting end of day report as: {decrypted_filename}")

def client_thread(connection, ip_address, port):
    process_connection(connection, ip_address)
    connection.close()

    connection_terminated_time = datetime.datetime.now().strftime("%H:%M:%S")            
    print(f"[-] Connection Terminated -> {connection_terminated_time} ({ip_address} : {port})")
    return

def start_server():
    clear_screen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("[+] Socket created.")

        try:
            server_socket.bind((server_connection.ip_address, server_connection.port))
            print("[+] Socket bind completed.")

        except socket.error as error:
            print(f"[!] Bind failed : { str(sys.exc_info()) }")
            print(error.with_traceback())
            sys.exit(1)

        server_socket.listen()
        print("[+] Socket is now listening.")

        try:
            while True:
                print("[+] Waiting for a new call at accept().")
                connection, address = server_socket.accept()
                ip_address, port = str(address[0]), str(address[1])

                connection_made_time = datetime.datetime.now().strftime("%H:%M:%S")            
                print(f"[+] Connection Made -> {connection_made_time} ({ip_address} : {port})")

                try: 
                    Thread(target = client_thread, args = (connection, ip_address, port)).start()

                except Exception as error:
                    print(f"[!] Threading error : {error}")
                    traceback.print_exc()

        except: pass
        return

server_connection = Connection("127.0.0.1", 4444)
command_from_client = Command()
server_data = Data()
server_side_security = Security()

start_server()