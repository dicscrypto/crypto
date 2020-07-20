import datetime
import sys
import socket
import time
import hashlib

from os import getcwd, system, path

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

        self.end_of_day_report_file = getcwd() + "\\day_end.txt"
        self.md5_of_end_of_day_report_file = ""

        self.encrypted_end_of_day_report_file = getcwd() + "\\day_end_encrypted.bin"
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
        self.private_key_file = getcwd() + "\\client_private.pem"
        self.public_key_file = getcwd() + "\\client_public.pem"

        self.server_public_key_file = getcwd() + "\\server_public.pem"

    def new_keys(self, key_size):
        random_generator = Random.new().read
        key = RSA.generate(key_size, random_generator)

        private_key, public_key = key, key.publickey()
        return private_key, public_key

    def encrypt(self, plaintext, public_key_file):
        public_key = RSA.import_key(open(public_key_file).read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        ciphertext = cipher_rsa.encrypt(plaintext)

        return ciphertext

    def encrypt_file(self, file_to_be_encrypted, destination_file):
        with open(file_to_be_encrypted, "rb") as file_to_encrypt:
            plaintext = file_to_encrypt.read()

        ciphertext = self.encrypt(plaintext, self.server_public_key_file)

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

def short_pause():
    time.sleep(1.5)

connect_to_server = Connection("127.0.0.1", 4444)
command_to_server = Command()
client_data = Data()
client_side_security = Security()

client_side_security.encrypt_file(client_data.end_of_day_report_file, client_data.encrypted_end_of_day_report_file)
upload_file(command_to_server.upload_end_of_day_report, client_data.encrypted_end_of_day_report_file)