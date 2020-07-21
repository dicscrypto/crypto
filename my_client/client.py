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

        self.encrypted_end_of_day_report_file = getcwd() + "\\day_end_encrypted.bin"
        self.md5_of_encrypted_end_of_day_report_file = ""

class Command:
    def __init__(self):
        self.download_menu = "download_menu"
        self.download_menu_hash = "download_menu_hash"

        self.download_server_public_key_file = "download_server_public_key_file"
        self.download_server_public_key_file_hash = "download_server_public_key_file_hash"

        self.upload_end_of_day_report = "upload_end_of_day_report"

        self.upload_encrypted_end_of_day_report_hash = "upload_encrypted_end_of_day_report_hash"

        self.create_private_and_public_key = "create_private_and_public_key"

        self.check_results_for_end_of_day_reports_upload = "check_results_for_end_of_day_reports_upload"

class Security:
    def __init__(self):
        self.private_key_file = getcwd() + "\\client_private.pem"
        self.public_key_file = getcwd() + "\\client_public.pem"

        self.server_public_key_file = getcwd() + "\\server_public.pem"
        self.md5_of_server_public_key_file = ""

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

def upload_data(command_to_be_sent, data_to_be_uploaded):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.sendall((command_to_be_sent.encode()))

        short_pause()
        client_socket.send(data_to_be_uploaded.encode())

def check_operation_results(command_to_be_sent):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.sendall((command_to_be_sent.encode()))

        server_reply = client_socket.recv(4096)

    return server_reply.decode()

def upload_end_of_day_report_and_perform_integrity_check():
    clear_screen()

    try:
        client_side_security.encrypt_file(client_data.end_of_day_report_file, client_data.encrypted_end_of_day_report_file)

        print(f"\nSuccessfully encrypted: {client_data.end_of_day_report_file}")
        client_data.md5_of_encrypted_end_of_day_report_file = client_side_security.get_file_hash(client_data.encrypted_end_of_day_report_file)

        print(f"\nMD5 Hash of encrypted end of day report file: {client_data.md5_of_encrypted_end_of_day_report_file}")
        upload_data(command_to_server.upload_encrypted_end_of_day_report_hash, client_data.md5_of_encrypted_end_of_day_report_file)

        short_pause()
        upload_file(command_to_server.upload_end_of_day_report, client_data.encrypted_end_of_day_report_file)
        print(f"\nSuccessfully uploaded: {client_data.encrypted_end_of_day_report_file}")

        short_pause()
        upload_operation_result = check_operation_results(command_to_server.check_results_for_end_of_day_reports_upload)

        if upload_operation_result == "ok": print("\nUpload successful")
        else: print("\nThere is something wrong with the uploading process or decryption of the report is unsuccessful.")

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

def create_private_and_public_key_on_server_and_download_server_public_key():
    clear_screen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))

        client_socket.sendall((command_to_server.create_private_and_public_key.encode()))
        print("(Create private and public key) Waiting for reply from Server...")

        server_reply = client_socket.recv(4096).decode()

        if server_reply == "ok": print("\nPrivate & Public key created on the Server side.")
        else: print("\nFailed creating Private & Public key on the Server side.")

        download_file(command_to_server.download_server_public_key_file, client_side_security.server_public_key_file)
        print("\nDownloading server public key...")

        client_side_security.md5_of_server_public_key_file = download_hash(command_to_server.download_server_public_key_file_hash)
        local_md5_of_server_public_key_file = client_side_security.get_file_hash(client_side_security.server_public_key_file)
        
        print("\nPerforming hash check on downloaded server public key file.\n")
        print(f"Local MD5 of Server's public keyfile: {local_md5_of_server_public_key_file}")
        print(f"Downloaded MD5 of Server's public keyfile: {client_side_security.md5_of_server_public_key_file}")

        if local_md5_of_server_public_key_file == client_side_security.md5_of_server_public_key_file: print("\nHash check passed.")
        else: print("\nHash check failed.")
        
    pause()

def pause():
    print()
    system("pause")

def short_pause():
    time.sleep(1.5)

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

        print("1. Create Private & Public Key on Server and Download Server's Public Key.")
        print("2. Download Menu & Perform Hash check.")
        print("3. Upload End of day report & Perform Hash check.")
        
        instructions = "\nOnly accepts digits."
        instructions += "\nEnter '0' to exit."
        instructions += "\n\nOption -> "

        try:
            option = int(input(instructions).strip())

            if option == 0: break
            elif option == 1: create_private_and_public_key_on_server_and_download_server_public_key()
            elif option == 2: download_menu_and_perform_integrity_check()
            elif option == 3: upload_end_of_day_report_and_perform_integrity_check()

        except ValueError:
            print("\nOnly accepts digits.")
            short_pause()

connect_to_server = Connection("127.0.0.1", 4444)
command_to_server = Command()
client_data = Data()
client_side_security = Security()

admin_menu()