import datetime
import sys
import socket
import time
import hashlib

from os import getcwd, system, path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto import Random
from base64 import b64encode, b64decode

class Connection:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = port

class Data:
    def __init__(self):
        self.menu_file = getcwd() + "\\menu.txt"
        self.md5_of_menu_file = ""
        self.end_of_day_report_file = getcwd() + "\\day_end.txt"
        self.encrypted_end_of_day_report_file = getcwd() + "\\day_end_encrypted.rsa"

class Command:
    def __init__(self):
        self.download_menu = "download_menu"
        self.download_menu_hash = "download_menu_hash"
        self.download_server_public_key_file = "download_server_public_key_file"
        self.download_server_public_key_file_hash = "download_server_public_key_file_hash"
        self.upload_end_of_day_report = "upload_end_of_day_report"
        self.upload_end_of_day_report_signature = "upload_end_of_day_report_signature"
        self.upload_client_public_key_file = "upload_client_public_key_file"
        self.create_private_and_public_key = "create_private_and_public_key"
        self.remotely_encrypt_server_private_key_file = "remotely_encrypt_server_private_key_file"
        self.shutdown_server = "shutdown_server"

class Security:
    def __init__(self):
        self.private_key_file = getcwd() + "\\client_private.pem" 
        self.private_key_file_encrypted = getcwd() + "\\client_private.aes"
        self.public_key_file = getcwd() + "\\client_public.pem" 
        self.md5_of_public_key_file = ""

        self.server_public_key_file = getcwd() + "\\server_public.pem"
        self.md5_of_server_public_key_file = ""

    def new_keys(self, key_size):
        random_generator = Random.new().read
        key = RSA.generate(key_size, random_generator)

        private_key, public_key = key, key.publickey()
        return private_key, public_key

    def create_private_and_public_key(self):
        private_key, public_key = self.new_keys(2048)

        private_key = private_key.export_key()
        public_key = public_key.export_key()

        with open(self.private_key_file, 'wb') as private_key_file: 
            private_key_file.write(private_key)

        print(f"Done creating Private Key: {self.private_key_file}")

        with open(self.public_key_file, 'wb') as public_key_file: 
            public_key_file.write(public_key)

        print(f"Done creating Public Key: {self.public_key_file}")

    def rsa_encrypt(self, plaintext, public_key): # RSA encryption.
        cipher_rsa = PKCS1_OAEP.new(public_key)
        ciphertext = cipher_rsa.encrypt(plaintext)

        return ciphertext

    def rsa_encrypt_file(self, file_to_be_encrypted, destination_file, public_key): # RSA encryption.
        with open(file_to_be_encrypted, "rb") as file_to_encrypt:
            plaintext = file_to_encrypt.read()

        ciphertext = self.rsa_encrypt(plaintext, public_key)
        ciphertext = b64encode(ciphertext) # Encode binary to base64 encoded text.

        with open(destination_file, "wb") as dest_file:
            dest_file.write(ciphertext)

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

    def sign(self, message, private_key):
        signer = PKCS1_v1_5.new(private_key)
        
        digest = MD5.new()
        digest.update(message)
        
        return signer.sign(digest)

    def verify(self, message, signature, public_key):
        signer = PKCS1_v1_5.new(public_key)

        digest = MD5.new()
        digest.update(message)

        return signer.verify(digest, signature)

def upload_file(command_to_be_sent, file_to_be_uploaded):
    file_to_be_uploaded_exists = path.exists(file_to_be_uploaded)

    if file_to_be_uploaded_exists:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
            client_socket.sendall((command_to_be_sent.encode()))

            short_pause()

            with open(file_to_be_uploaded, "rb") as file_to_upload:
                data = file_to_upload.read()

            client_socket.send(data)

    else:
        print(f"[!] File not found: {file_to_be_uploaded}")
        sys.exit(1)

def upload_data(command_to_be_sent, data_to_be_uploaded):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.sendall((command_to_be_sent.encode()))

        short_pause()
        client_socket.send(data_to_be_uploaded.encode())

def upload_signature(command_to_be_sent, signature_to_be_uploaded):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.sendall((command_to_be_sent.encode()))

        short_pause()
        client_socket.send(signature_to_be_uploaded)

def upload_end_of_day_report_and_perform_integrity_check():
    clear_screen()

    try:
        upload_file(command_to_server.upload_client_public_key_file, client_side_security.public_key_file)
        print(f"\nUploaded client's public key file: {client_side_security.public_key_file}")

        download_file(command_to_server.download_server_public_key_file, client_side_security.server_public_key_file)
        print(f"\nDownloaded server's public key file: {client_side_security.server_public_key_file}")

        server_public_key = RSA.import_key(open(client_side_security.server_public_key_file).read())
        client_side_security.rsa_encrypt_file(client_data.end_of_day_report_file, client_data.encrypted_end_of_day_report_file, server_public_key)
        print(f"\nSuccessfully encrypted: {client_data.end_of_day_report_file}")

        long_pause()

        data = open(client_data.encrypted_end_of_day_report_file, "rb").read()
        client_private_key = RSA.import_key(open(client_side_security.private_key_file).read())
        end_of_day_report_signature = b64encode(client_side_security.sign(data, client_private_key))

        print(f"\nData signed with private key: {end_of_day_report_signature.decode()}")

        upload_signature(command_to_server.upload_end_of_day_report_signature, end_of_day_report_signature)
        print("\nSuccessfully uploaded signature.")

        upload_file(command_to_server.upload_end_of_day_report, client_data.encrypted_end_of_day_report_file)
        print(f"\nSuccessfully uploaded: {client_data.encrypted_end_of_day_report_file}")

        pause()

    except Exception as error:
        print(f"Encountered error while performing operation: {error}")
        sys.exit(1)

def download_file(command_to_be_sent, file_to_be_downloaded):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.sendall((command_to_be_sent.encode()))

        data = client_socket.recv(4096)

        with open(file_to_be_downloaded, "wb") as file_to_download:
            file_to_download.write(data)

def download_hash(command_to_be_sent):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.sendall((command_to_be_sent.encode()))

        downloaded_hash = client_socket.recv(4096).decode()

    return downloaded_hash

def download_menu_and_perform_integrity_check():
    clear_screen()

    try:
        download_file(command_to_server.download_menu, client_data.menu_file)
        md5_of_menu_file_from_server = download_hash(command_to_server.download_menu_hash)
        local_md5_of_menu_file = client_side_security.get_file_hash(client_data.menu_file)

        print(f"Local MD5 of menu file: {local_md5_of_menu_file}")
        print(f"MD5 of menu file from server: {md5_of_menu_file_from_server}")

        if local_md5_of_menu_file == md5_of_menu_file_from_server: print("\nHash check passed.")
        else: print("\nHash check failed.")

        pause()

    except Exception as error:
        print(f"Encountered error while performing operation: {error}")
        sys.exit(1)

def remotely_encrypt_server_private_key_file():
    while True:
        clear_screen()

        password = input("Enter the password used to encrypted server's private key file -> ").strip()
        repeat_password = input("Enter the password again that is used to encrypt server's private key file -> ").strip()

        if repeat_password == password:
            password = hashlib.sha256(password.encode()).digest()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
                client_socket.sendall((command_to_server.remotely_encrypt_server_private_key_file.encode()))

                short_pause()

                client_socket.send(password)

                short_pause()

                server_reply = client_socket.recv(4096).decode()

                if server_reply == "private key encryption ok":
                    print("\nSuccessfully encrypted server's private key file.")
                    print("Server will now terminate. Please relaunch client after starting up server.")
                    sys.exit(0)

        else: 
            print("\nPlease ensure that both passwords matches.")
            short_pause()

def create_private_and_public_key_on_server_and_download_server_public_key():
    clear_screen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))

        client_socket.sendall((command_to_server.create_private_and_public_key.encode()))
        print("(Create private and public key) Waiting for reply from Server...")

        server_reply = client_socket.recv(4096).decode()

        if server_reply == "ok": 
            print("\nPrivate & Public key created on the Server side.")

            download_file(command_to_server.download_server_public_key_file, client_side_security.server_public_key_file)
            print("\nDownloading server public key...")

            client_side_security.md5_of_server_public_key_file = download_hash(command_to_server.download_server_public_key_file_hash)
            local_md5_of_server_public_key_file = client_side_security.get_file_hash(client_side_security.server_public_key_file)
            
            print("\nPerforming hash check on downloaded server public key file.\n")
            print(f"Local MD5 of Server's public keyfile: {local_md5_of_server_public_key_file}")
            print(f"Downloaded MD5 of Server's public keyfile: {client_side_security.md5_of_server_public_key_file}")

            if local_md5_of_server_public_key_file == client_side_security.md5_of_server_public_key_file: 
                print("\nHash check passed.")
            else: 
                print("\nHash check failed.")
            
            remotely_encrypt_server_private_key_file()

        else: 
            print("\nFailed creating Private & Public key on the Server side.")
        
    pause()

def shutdown_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.send(command_to_server.shutdown_server.encode())

    print("\nShutting down server. Exiting client.")
    short_pause()
    sys.exit(0)

def pause():
    print()
    system("pause")

def short_pause():
    time.sleep(1.5)

def long_pause():
    time.sleep(3)

def clear_screen():
    system("cls")

def print_header(header_message):
    print("=" * 64)
    print(header_message)
    print("=" * 64)

def admin_menu():
    while True:
        clear_screen()
        print_header("Admin Menu")

        print("1. Create Key pair on Server.")
        print("2. Create Key pair on Client.")
        print("3. Download Menu.")
        print("4. Upload End of day report.")
        print("5. Shutdown Server.")
        
        instructions = "\nOnly accepts digits."
        instructions += "\nEnter '0' to exit."
        instructions += "\n\nOption -> "

        try:
            option = int(input(instructions).strip())

            if option == 0: break
            elif option == 1: create_private_and_public_key_on_server_and_download_server_public_key()
            
            elif option == 2: 
                clear_screen()
                client_side_security.create_private_and_public_key()
                pause()

            elif option == 3: download_menu_and_perform_integrity_check()
            elif option == 4: upload_end_of_day_report_and_perform_integrity_check()
            elif option == 5: shutdown_server()

        except ValueError:
            print("\nOnly accepts digits.")
            short_pause()

connect_to_server = Connection("127.0.0.1", 4444)
command_to_server = Command()
client_data = Data()
client_side_security = Security()

admin_menu()