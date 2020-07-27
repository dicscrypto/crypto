import datetime
import sys
import socket
import time
import hashlib
import traceback

from os import getcwd, system, path, remove

# from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class Connection:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address 
        self.port = port 

class Data:
    def __init__(self):
        self.menu_file = getcwd() + "\\menu.txt" 
        self.md5_of_menu_file = "" 
        self.end_of_day_report_base = getcwd() + "\\day_end_" 
        self.encrypted_end_of_day_report_file_base = getcwd() + "\\day_end_encrypted_" 
        self.md5_of_encrypted_end_of_day_report_file = ""
        self.end_of_day_report_upload_results = ""

class Command:
    def __init__(self):
        # Various commands which will be used to process commands that was sent from client.
        self.download_menu = "download_menu"
        self.download_menu_hash = "download_menu_hash"
        self.download_server_public_key_file = "download_server_public_key_file"
        self.download_server_public_key_file_hash = "download_server_public_key_file_hash"
        self.upload_end_of_day_report = "upload_end_of_day_report"
        self.upload_encrypted_end_of_day_report_hash = "upload_encrypted_end_of_day_report_hash"
        self.create_private_and_public_key = "create_private_and_public_key"
        self.check_results_for_end_of_day_reports_upload = "check_results_for_end_of_day_reports_upload"
        self.remotely_encrypt_server_private_key_file = "remotely_encrypt_server_private_key_file"
        self.shutdown_server = "shutdown_server"

class Security:
    def __init__(self):
        self.private_key_file = getcwd() + "\\server_private.pem" 
        self.private_key_file_encrypted = getcwd() + "\\server_private.aes"
        self.public_key_file = getcwd() + "\\server_public.pem" 
        self.md5_of_public_key_file = ""

    def new_keys(self, key_size):
        random_generator = Random.new().read
        key = RSA.generate(key_size, random_generator)

        private_key, public_key = key, key.publickey()
        return private_key, public_key

    def pad(self, plaintext):
        # AES.block_size = 16
        padding_length = AES.block_size - len(plaintext) % AES.block_size   
        padded_plaintext = plaintext + b"\0" * padding_length # b"\0" : NULL

        return padded_plaintext

    def aes_encrypt(self, plaintext, password):
        #private_key = hashlib.sha256(password.encode()).digest() # For local use.
        private_key = password  # For remote use.
        padded_plaintext = self.pad(plaintext)
        iv = Random.new().read(AES.block_size)

        cipher_aes = AES.new(private_key, AES.MODE_CBC, iv)
        ciphertext = b64encode(iv + cipher_aes.encrypt(padded_plaintext))

        return ciphertext  

    def aes_encrypt_file(self, password, file_to_be_encrypted, destination_file):
        with open(file_to_be_encrypted, "rb") as file_to_encrypt: 
            plaintext =  file_to_encrypt.read()

        ciphertext = self.aes_encrypt(plaintext, password) 

        with open(destination_file, "wb") as dest_file: 
            dest_file.write(ciphertext)

        print(f"[@] Encrypted \"{file_to_be_encrypted}\" TO \"{destination_file}\" ")

        remove(file_to_be_encrypted) # Remove the original plaintext file from disk.

        print(f"[@] Removed original file \"{file_to_be_encrypted}\"")

    def aes_decrypt(self, ciphertext, password):
        private_key = hashlib.sha256(password.encode()).digest()
        ciphertext = b64decode(ciphertext) # Decode to binary.
        iv = ciphertext[:16] # First 16 bytes.
        
        cipher_aes = AES.new(private_key, AES.MODE_CBC, iv)

        plaintext = cipher_aes.decrypt(ciphertext[16:]) # After 16 bytes.
        plaintext = plaintext.rstrip(b"\0") # Strips paddings/NULL.

        return plaintext

    def aes_decrypt_file(self, password, file_to_be_decrypted, destination_file):
        with open(file_to_be_decrypted, "rb") as file_to_decrypt:
            ciphertext = file_to_decrypt.read() 
        
        plaintext = self.aes_decrypt(ciphertext, password) 

        with open(destination_file, "wb") as dest_file: 
            dest_file.write(plaintext)

    def decrypt(self, ciphertext): # RSA decryption.
        private_key = RSA.import_key(open(self.private_key_file).read())

        cipher_rsa = PKCS1_OAEP.new(private_key)
        plaintext = cipher_rsa.decrypt(ciphertext)

        return plaintext.decode()

    def decrypt_file(self, file_to_be_decrypted, destination_file): # RSA decryption.
        with open(file_to_be_decrypted, "rb") as file_to_decrypt:
            ciphertext = file_to_decrypt.read()

        ciphertext = b64decode(ciphertext) 
        plaintext = self.decrypt(ciphertext) 

        with open(destination_file, "w") as dest_file: 
            dest_file.write(plaintext)

    def create_private_and_public_key(self):
        private_key, public_key = self.new_keys(2048)

        private_key = private_key.export_key()
        public_key = public_key.export_key()

        with open(self.private_key_file, 'wb') as private_key_file: 
            private_key_file.write(private_key)

        print(f"[X] Done creating Private Key: {self.private_key_file}")

        with open(self.public_key_file, 'wb') as public_key_file: 
            public_key_file.write(public_key)

        print(f"[X] Done creating Public Key: {self.public_key_file}")

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

def check_error_after_decryption(destination_file):
    with open(destination_file, "rb") as dest_file:
        data = dest_file.read()

    if b"-----BEGIN RSA PRIVATE KEY-----" in data: return "ok" # If this string is present, most likely decryption is successful.
    else: return "failed"

def send_file(connection, file_to_be_sent):
    file_to_be_sent_exists = path.exists(file_to_be_sent)

    if file_to_be_sent_exists:
        with open(file_to_be_sent, "rb") as file_to_send: 
            data = file_to_send.read()

        connection.sendall(data)

    else:
        print(f"[!] File not found: {file_to_be_sent}")
        sys.exit(1) # Exit with error.

def download_file(connection, destination_file): 
    data = connection.recv(4096)

    with open(destination_file, "wb") as dest_file:
        dest_file.write(data)

def get_formatted_date_and_time():
    now = datetime.datetime.now()
    formatted_date_and_time = now.strftime("%Y-%m-%d_%H%M")

    return(formatted_date_and_time)

def process_connection(connection, ip_address): 
    user_command = connection.recv(4096).decode()

    if user_command == command_from_client.download_menu_hash:
        server_data.md5_of_menu_file = server_side_security.get_file_hash(server_data.menu_file)
        connection.sendall(server_data.md5_of_menu_file.encode())

        print("<< Completed: [Sending] default menu hash. >>")
        return

    elif user_command == command_from_client.download_menu:
        send_file(connection, server_data.menu_file)

        print("<< Completed: [Sending] default menu. >>")
        return

    elif user_command == command_from_client.download_server_public_key_file_hash:
        server_side_security.md5_of_public_key_file = server_side_security.get_file_hash(server_side_security.public_key_file)
        connection.sendall(server_side_security.md5_of_public_key_file.encode())

        print("<< Completed: [Sending] public key file hash. >>")
        return

    elif user_command == command_from_client.download_server_public_key_file:
        send_file(connection, server_side_security.public_key_file)

        print("<< Completed: [Sending] public key file. >>")
        return

    elif user_command == command_from_client.upload_encrypted_end_of_day_report_hash:
        end_of_day_encrypted_report_hash = connection.recv(4096).decode()
        server_data.md5_of_encrypted_end_of_day_report_file = end_of_day_encrypted_report_hash

        print(f"[O] (Downloaded) End of day encrypted report hash: {server_data.md5_of_encrypted_end_of_day_report_file}")
        return

    elif user_command == command_from_client.upload_end_of_day_report:
        encrypted_end_of_day_report_filename = server_data.encrypted_end_of_day_report_file_base + ip_address + " - " + get_formatted_date_and_time() + ".rsa"
        download_file(connection, encrypted_end_of_day_report_filename)

        print(f"[+] Saving encrypted end of day report as: {encrypted_end_of_day_report_filename}")

        try:
            local_md5_of_encrypted_end_of_day_report_file = server_side_security.get_file_hash(encrypted_end_of_day_report_filename)
            print(f"[O] (Local) Encrypted End of day report hash: {local_md5_of_encrypted_end_of_day_report_file}")

            if local_md5_of_encrypted_end_of_day_report_file == server_data.md5_of_encrypted_end_of_day_report_file:
                print("[+] Hash check for encrypted end of day report file: ok")

                decrypted_filename = server_data.end_of_day_report_base + ip_address + " - " + get_formatted_date_and_time() + ".txt"
                server_side_security.decrypt_file(encrypted_end_of_day_report_filename, decrypted_filename)
                
                server_data.end_of_day_report_upload_results = "ok"
                print(f"[+] Decrypting end of day report as: {decrypted_filename}")

            else:
                server_data.end_of_day_report_upload_results = "not ok"
                print("[!] Hash check for encrypted end of day report file: failed")     

        except Exception as error:
            server_data.end_of_day_report_upload_results = "not ok"

            print(f"[~] Unable to decrypt: {encrypted_end_of_day_report_filename} , please check your public/private key pair.")
            print(f"[~] Error: {error}")

        return

    elif user_command == command_from_client.check_results_for_end_of_day_reports_upload:
        connection.sendall(server_data.end_of_day_report_upload_results.encode())

        print("<< Completed: [Sending] end of day reports upload result. >>")
        return

    elif user_command == command_from_client.create_private_and_public_key:
        server_side_security.create_private_and_public_key()
        
        connection.send(b"ok")
        return

    elif user_command == command_from_client.remotely_encrypt_server_private_key_file:
        password = connection.recv(4096)
        server_side_security.aes_encrypt_file(password, server_side_security.private_key_file, server_side_security.private_key_file_encrypted)

        print("<< Completed: [Encrypting] server private key file. >>")
        print("[!] Please restart the server application again.")

        connection.send(b"private key encryption ok")
        return "restart server"

    elif user_command == command_from_client.shutdown_server:
        print("[!!!] Shutdown signal received. Server shutting down.")
        short_pause()

        remove(server_side_security.private_key_file)
        print(f"[!!] Removed {server_side_security.private_key_file}")
        short_pause()

        sys.exit(0)

def connection_handler(connection, ip_address, port):
    return_code = process_connection(connection, ip_address)
    connection.close()

    connection_terminated_time = datetime.datetime.now().strftime("%H:%M:%S")            
    print(f"[-] Connection Terminated -> {connection_terminated_time} ({ip_address} : {port})")

    if return_code == "restart server": return "restart_server"
    else: return

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
                    return_code = connection_handler(connection, ip_address, port)

                    if return_code == "restart_server": 
                        print("[!] Restart signal received. Server will now restart.")
                        short_pause()
                        break

                except Exception as error:
                    print(f"[!] Error occured : {error}")
                    traceback.print_exc()

        except: pass
        return

def print_header(header_message):
    print("=" * 64)
    print(header_message)
    print("=" * 64)

def initialise():
    while True:
        clear_screen()
        print_header("Server Login Screen")
        
        password = input("<!> Input password to decrypt private key file: ").strip()
        server_side_security.aes_decrypt_file(password, server_side_security.private_key_file_encrypted, server_side_security.private_key_file)

        decrypting_result = check_error_after_decryption(server_side_security.private_key_file)

        if decrypting_result == "ok": start_server()

        else:
            print("\nWrong password.")
            short_pause()

server_connection = Connection("127.0.0.1", 4444)
command_from_client = Command()
server_data = Data()
server_side_security = Security()

initialise()