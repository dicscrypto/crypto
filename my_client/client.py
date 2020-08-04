import datetime
import sys
import socket
import time
import hashlib
import re

from os import getcwd, system, path, remove
from base64 import b64encode, b64decode
from datetime import date
from calendar import day_name
from subprocess import Popen

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256

class Connection:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = port

class Data:
    weekdays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    current_day = day_name[date.today().weekday()]
   
    def __init__(self):
        self.menu_file = getcwd() + "\\menu.txt"
        self.end_of_day_report_file = getcwd() + "\\day_end.txt"
        self.encrypted_end_of_day_report_file = getcwd() + "\\day_end_encrypted.rsa"
        
        self.food_dict = dict()
        self.todays_food_menu_dict = dict()
        self.search_hits_dict = dict()
        self.ordered_food_dict = dict()
        self.food_cart = dict()
        self.day_end_dict = dict()

        self.md5_of_menu_file = ""

    def load_data_from_file(self):
        menu_file_exist = path.exists(self.menu_file)

        if menu_file_exist:
            food_data = open(self.menu_file).readlines()
            return food_data
        
        else:
            print(f"[!] Menu file not found:\n{self.menu_file}")
            sys.exit(1)

    def load_data_to_nested_dict(self, food_data):
        temp_food_dict = dict()

        for day_of_the_week in self.weekdays:
            food_name_and_price_dict = dict()

            for food in food_data:
                food_day, food_name, food_price = food.split(',')

                if food_day == day_of_the_week:
                    food_name_and_price_dict[food_name] = float(food_price)
    
            temp_food_dict[day_of_the_week] = food_name_and_price_dict

        return temp_food_dict

    def get_todays_menu(self):
        self.todays_food_menu_dict = self.food_dict.get(self.current_day)

class Command:
    def __init__(self):
        self.download_menu = "download_menu"
        self.download_menu_hash = "download_menu_hash"
        self.download_server_public_key_file = "download_server_public_key_file"
        self.download_server_public_key_file_hash = "download_server_public_key_file_hash"

        self.upload_end_of_day_report = "upload_end_of_day_report"
        self.upload_end_of_day_report_signature = "upload_end_of_day_report_signature"
        self.upload_authentication_details_signature = "upload_authentication_details_signature"
        self.upload_client_public_key_file = "upload_client_public_key_file"
        self.upload_client_public_key_hash = "upload_client_public_key_hash"

        self.create_private_and_public_key = "create_private_and_public_key"
        self.remotely_encrypt_server_private_key_file = "remotely_encrypt_server_private_key_file"
        self.shutdown_server = "shutdown_server"
        self.user_login = "user_login"

class Security:
    def __init__(self):
        self.private_key_file = getcwd() + "\\client_private.pem" 
        self.private_key_file_encrypted = getcwd() + "\\client_private.aes"
        self.public_key_file = getcwd() + "\\client_public.pem" 
        self.server_public_key_file = getcwd() + "\\server_public.pem"

        self.md5_of_public_key_file = ""
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

        print(f"** Done creating Private Key:\n{self.private_key_file}")

        with open(self.public_key_file, 'wb') as public_key_file: 
            public_key_file.write(public_key)

        print(f"** Done creating Public Key:\n{self.public_key_file}")

    def pad(self, plaintext):
        # AES.block_size = 16
        padding_length = AES.block_size - len(plaintext) % AES.block_size   
        padded_plaintext = plaintext + b"\0" * padding_length # b"\0" : NULL

        return padded_plaintext

    def aes_encrypt(self, plaintext, password):
        private_key = hashlib.sha256(password.encode()).digest() # For local use.
        #private_key = password  # For remote use.
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

        print(f"\n** Encrypted -> \"{file_to_be_encrypted}\" TO \"{destination_file}\" ")

        remove(file_to_be_encrypted) # Remove the original plaintext file from disk.

        print(f"\n** Removed original file \"{file_to_be_encrypted}\"")

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

    def rsa_decrypt(self, ciphertext, private_key): # RSA decryption.
        cipher_rsa = PKCS1_OAEP.new(private_key)
        plaintext = cipher_rsa.decrypt(ciphertext)

        return plaintext.decode()

    def rsa_decrypt_file(self, file_to_be_decrypted, destination_file, private_key): # RSA decryption.
        with open(file_to_be_decrypted, "rb") as file_to_decrypt:
            ciphertext = file_to_decrypt.read()

        ciphertext = b64decode(ciphertext) 
        plaintext = self.rsa_decrypt(ciphertext, private_key) 

        with open(destination_file, "w", newline = "\n") as dest_file: 
            dest_file.write(plaintext)

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
        digest = SHA256.new(message)
        signature = pss.new(private_key).sign(digest)

        return signature

    def verify(self, message, signature, public_key):
        digest = SHA256.new(message)
        verifier = pss.new(public_key)
        signature = b64decode(signature)

        try:
            verifier.verify(digest, signature)
            return True
        
        except (ValueError, TypeError):
            return False

    def password_check(self, new_password):
        lower_regex = re.compile(r'[a-z]+')
        upper_regex = re.compile(r'[A-Z]+')
        digit_regex = re.compile(r'[0-9]+')
        special_char_regex = re.compile(r'\W+')

        error = ''

        if len(new_password) < 8:
            error += "\nPassword must contain at least 8 characters."

        if lower_regex.findall(new_password) == []:
            error += "\nPassword must contain at least one lowercase character."

        if upper_regex.findall(new_password) == []:
            error += "\nPassword must contain at least one uppercase character." 

        if digit_regex.findall(new_password) == []:
            error += "\nPassword must contain at least one digit."

        if special_char_regex.findall(new_password) == []:
            error += "\nPassword must contain at least one special character."

        return error

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
        client_public_key_hash = client_side_security.get_file_hash(client_side_security.public_key_file)
        upload_data(command_to_server.upload_client_public_key_hash, client_public_key_hash)
        print(f"\n** Uploaded MD5 of Client's public key file: {client_public_key_hash}")

        upload_file(command_to_server.upload_client_public_key_file, client_side_security.public_key_file)
        print(f"\n** Uploaded client's public key file:\n{client_side_security.public_key_file}")

        download_file(command_to_server.download_server_public_key_file, client_side_security.server_public_key_file)
        print(f"\n** Downloaded server's public key file:\n{client_side_security.server_public_key_file}")

        server_public_key = RSA.import_key(open(client_side_security.server_public_key_file).read())
        client_side_security.rsa_encrypt_file(client_data.end_of_day_report_file, client_data.encrypted_end_of_day_report_file, server_public_key)
        print(f"\n** Successfully encrypted:\n{client_data.end_of_day_report_file}")

        long_pause()

        data = open(client_data.encrypted_end_of_day_report_file, "rb").read()
        client_private_key = RSA.import_key(open(client_side_security.private_key_file).read())
        end_of_day_report_signature = b64encode(client_side_security.sign(data, client_private_key))
        print(f"\n** Data signed with private key:\n{end_of_day_report_signature.decode()}")

        upload_signature(command_to_server.upload_end_of_day_report_signature, end_of_day_report_signature)
        print("\n** Successfully uploaded signature.")

        upload_file(command_to_server.upload_end_of_day_report, client_data.encrypted_end_of_day_report_file)
        print(f"\n** Successfully uploaded:\n{client_data.encrypted_end_of_day_report_file}")

        remove(client_data.encrypted_end_of_day_report_file)
        print(f"\n** Removed:\n{client_data.encrypted_end_of_day_report_file}")

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

def download_menu_and_load_food_data_into_nested_dict():
    download_menu_and_perform_integrity_check()
    food_data = client_data.load_data_from_file()
    client_data.food_dict = client_data.load_data_to_nested_dict(food_data)

def download_menu_and_perform_integrity_check():
    clear_screen()

    try:
        download_file(command_to_server.download_menu, client_data.menu_file)
        md5_of_menu_file_from_server = download_hash(command_to_server.download_menu_hash)
        local_md5_of_menu_file = client_side_security.get_file_hash(client_data.menu_file)

        print(f"** Local MD5 of menu file: {local_md5_of_menu_file}")
        print(f"** MD5 of menu file from server: {md5_of_menu_file_from_server}")

        if local_md5_of_menu_file == md5_of_menu_file_from_server: print("\n** Hash check: Passed")
        else: print("\n** Hash check: Failed")

        pause()

    except Exception as error:
        print(f"Encountered error while performing operation: {error}")
        sys.exit(1)

def download_server_public_key():
    download_file(command_to_server.download_server_public_key_file, client_side_security.server_public_key_file)
    print("\n** Downloading server public key.")

    client_side_security.md5_of_server_public_key_file = download_hash(command_to_server.download_server_public_key_file_hash)
    local_md5_of_server_public_key_file = client_side_security.get_file_hash(client_side_security.server_public_key_file)
    
    print("\n** Performing hash check on downloaded server public key file.\n")
    print(f"** Local MD5 of Server's public keyfile: {local_md5_of_server_public_key_file}")
    print(f"** Downloaded MD5 of Server's public keyfile: {client_side_security.md5_of_server_public_key_file}")

    if local_md5_of_server_public_key_file == client_side_security.md5_of_server_public_key_file: 
        print("\n** Hash check passed.")
        return "pass"

    else: 
        print("\n[!] Hash check failed.")
        return "fail"

def create_private_and_public_key_on_server_and_download_server_public_key():
    clear_screen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))

        client_socket.sendall((command_to_server.create_private_and_public_key.encode()))
        print("** Remotely creating private and public key.")
        print("** Waiting for reply from Server.")

        server_reply = client_socket.recv(4096).decode()

        if server_reply == "ok": 
            print("\n** Private & Public key created on the Server side.")
            
            return_code = download_server_public_key()

            if return_code == "pass": remotely_encrypt_server_private_key_file()
            else:
                print("[!] Server public key file is corrupted.")
                pause()

        else: 
            print("\nFailed creating Private & Public key on the Server side.")
        
    pause()

def shutdown_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
        client_socket.send(command_to_server.shutdown_server.encode())

    print("\n** Shutting server down.")
    print("** Performing logout now.")

    logout()
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

def remotely_encrypt_server_private_key_file():
    while True:
        clear_screen()

        password = input("** Enter the password used to encrypted server's private key file -> ").strip()
        error = client_side_security.password_check(password)

        if error == "":
            repeat_password = input("** Enter the password again that is used to encrypt server's private key file -> ").strip()

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
                        print("\n** Successfully encrypted server's private key file.")
                        print("\n** Server will now restart. Please relaunch client after starting up server.")
                        sys.exit(0)

            else: 
                print("\nPlease ensure that both passwords matched.")
                short_pause()

        else:
            print(error)
            pause()

def locally_encrypt_client_private_key_file():
    while True:
        clear_screen()
        print_header("Create password for client's private key file.")

        instructions = "Password requirements:"
        instructions += "\n\nMin 8 characters in length."
        instructions += "\n1 uppercase, 1 lowercase, 1 digit, 1 special char.\n"

        print(instructions)

        password = input("** Please enter password -> ").strip()

        error = client_side_security.password_check(password)

        if error == "":
            repeat_password = input("** Please re-enter password again -> ").strip()

            if repeat_password == password:
                client_side_security.aes_encrypt_file(password, client_side_security.private_key_file, client_side_security.private_key_file_encrypted)
                pause()
                return "break"
            
            else:
                print("\nPlease ensure that both passwords matched.")
                short_pause()

        else:
            print(error)
            pause()

def check_error_after_decryption(destination_file):
    with open(destination_file, "rb") as dest_file:
        data = dest_file.read()

    if b"-----BEGIN RSA PRIVATE KEY-----" in data: return "ok" # If this string is present, most likely decryption is successful.
    else: return "failed"

def list_order():
    while True:
        clear_screen()
        print_header("Order")
        amount_to_pay = list_cart(client_data.food_cart)

        instructions = "\np - payment\nc - clear cart\nb - previous menu"
        instructions += "\nOther inputs will not be accepted."
        instructions += "\n\nOption -> "

        option = input(instructions).strip()

        if option == 'c':
            client_data.food_cart.clear()
            print("\nCart cleared!")
            pause()
            break

        elif option == 'b': break

        elif option == 'p':
            if make_payment(amount_to_pay) == "payment made":
                client_data.food_cart.clear()
                break

        else:
            print("\nOnly 'p', 'c', 'b' are accepted.")
            short_pause()

def list_cart(food_dict):
    total_price = 0

    for count, food_name in enumerate(food_dict, 1):
        price_and_quantity_list = food_dict.get(food_name)
        food_price = price_and_quantity_list[0]
        food_quantity = price_and_quantity_list[1]
        food_price *= food_quantity
        total_price += food_price

        print(f"{count}. {food_name} X {str(food_quantity).ljust(35)} ${food_price:.2f}")

    net_price = total_price
    total_price = f"${total_price:.2f}"
    print_header(f"Total {total_price.rjust(55)}")

    return net_price

def list_food(food_dict):
    for count, food_name in enumerate(food_dict, 1):
        food_price = food_dict.get(food_name)
        print(f"{count}. {food_name.ljust(35)} ${food_price:.2f}")
 
def update_day_end():
    for food_name in client_data.food_cart:
        price_and_quantity_list = client_data.food_cart.get(food_name)
        food_quantity = price_and_quantity_list[1]

        if food_name in client_data.day_end_dict:
            updated_quantity = client_data.day_end_dict.get(food_name) + food_quantity
            client_data.day_end_dict[food_name] = updated_quantity

        else: client_data.day_end_dict[food_name] = food_quantity

    data_to_write = ""
    with open(client_data.end_of_day_report_file, "w") as report_to_write:
        for food_name in client_data.day_end_dict:
            food_quantity = client_data.day_end_dict.get(food_name)
            data_to_write += f"{food_name},{food_quantity}\n"

        report_to_write.write(data_to_write.strip())
    
    Popen(["notepad.exe", client_data.end_of_day_report_file])

def make_payment(amount_to_pay):
    while True:
        clear_screen()
        print_header("Payment")

        print(f"Amount to pay -> ${amount_to_pay:.2f}")

        instructions = "\nOnly digits(floating points) are accepted."
        instructions += "\nEnter \"0\" to cancel payment."
        instructions += "\n\nPlease enter amount to pay -> $"

        try:
            amount_from_customer = float(input(instructions).strip())

            if amount_from_customer == 0:
                print("\nYou have chosen to cancel payment.")
                short_pause()
                break

            elif amount_from_customer < amount_to_pay:
                print("\nPlease provide exact amount or more.")
                short_pause()

            else:
                customers_change = amount_from_customer - amount_to_pay
                print(f"\nChange -> ${customers_change:.2f}")
                print("\nThank you for supporting SPAM!")
                
                update_day_end()

                pause()
                return "payment made"

        except ValueError:
            print("\nOnly digits(floating points) are accepted.")
            short_pause()

def specify_quantity(ordered_food_name, ordered_food_price):
    clear_screen()
    print_header(f"{ordered_food_name}'s page")

    try:
        instructions = "Only digits are accepted."
        instructions += "\nMin order - 1, Max order - 10"
        instructions += "\nEnter \"0\" to go back to the previous menu."
        instructions += "\n\nQuantity -> "

        order_quantity = int(input(instructions).strip())

        if order_quantity == 0:
            print(f"\nYou have cancelled ordering {ordered_food_name}.")
            short_pause()
            return "break"

        elif order_quantity < 0:
            print("\nNegative values are not accepted.")
            short_pause()

        elif order_quantity > 10:
            print("\nExcessive quantity are not accepted.")
            short_pause()

        else:
            price_and_quantity_list = [ordered_food_price, order_quantity]
            client_data.food_cart[ordered_food_name] = price_and_quantity_list

            print(f"\nSuccessfully added {ordered_food_name} X {order_quantity} to the cart.")
            pause()
            return "break"

    except ValueError:
        print("\nQuantity must be in digits.")
        print("In addition, check min\\max digits.")
        short_pause()

def order_food():
    while True:
        clear_screen()
        print_header("Order Food")
        list_food(client_data.search_hits_dict)

        try:
            instructions = "\nEnter \"0\" to exit."
            instructions += "\nOnly digits are accepted."
            instructions += "\n\nOption -> "

            option = int(input(instructions).strip())

            if option == 0: break

            elif option < 1 or option > len(client_data.search_hits_dict):
                print("\nInvalid option.")
                short_pause()
            
            else:
                for count, food_name in enumerate(client_data.search_hits_dict, 1):
                    if option == count:
                        ordered_food_name = food_name
                        ordered_food_price = client_data.search_hits_dict.get(food_name)
                        break

                return_code = specify_quantity(ordered_food_name, ordered_food_price)

                if return_code == "break": break

        except ValueError:
            print("\nOnly digits are accepted.")
            short_pause()

def search_food():
    while True:
        clear_screen()
        print_header("Order Food")
        client_data.search_hits_dict.clear()

        instructions = "Only letters and spaces are accepted."
        instructions += "\nEnter \"exit\" to go back to the previous menu."
        instructions += "\n\nFood to search -> "

        food_to_search = input(instructions).lower().strip()

        # Regex that only accepts letters and spaces.
        regex = r"^[A-Za-z ]*$"
        passed_regex = re.match(regex, food_to_search)

        if passed_regex and food_to_search != "":
            if food_to_search == "exit": break

            for food_name in client_data.todays_food_menu_dict:
                if food_to_search in food_name.lower():
                    client_data.search_hits_dict[food_name] = client_data.todays_food_menu_dict.get(food_name)
            
            if len(client_data.search_hits_dict) > 0:
                order_food()

            else:
                print(f"\nNo food that is similar to {food_to_search} found.")
                short_pause()

        else:
            print("\nOnly accepts alphabets and spaces.")
            print("\nInput must also not be empty.")
            short_pause()

def display_todays_menu():
    clear_screen()
    print_header(f"{client_data.current_day}'s Food")
    list_food(client_data.todays_food_menu_dict)
    pause()

def decrypt_end_of_day_report():
    encrypted_end_of_day_report_file_exist = path.exists(client_data.encrypted_end_of_day_report_file)

    if encrypted_end_of_day_report_file_exist:
        client_private_key = RSA.import_key(open(client_side_security.private_key_file).read())
        client_side_security.rsa_decrypt_file(client_data.encrypted_end_of_day_report_file, client_data.end_of_day_report_file, client_private_key)
        remove(client_data.encrypted_end_of_day_report_file)
        
        print(f"\n** Decrypted end of day report after logging in:\n{client_data.encrypted_end_of_day_report_file}")
        pause()

def about_us():
    clear_screen()
    
    message = "     P7358646 - Suhairy Bin Subori\n"
    message += "    P7358504 - Muhammad Hairul Anuar Bin Misni\n"
    message += "    P7358695 - Muhammad Sadiq Bin Murakay\n"
    message += "    P7358686 - Mohammad Nor ‘Amin Bin Kasmuri\n"
    message += "    P7358696 - Muhammad Fadzli Bin Roslan\n"
    message += "    We... are... the... A.... Team!!!"
    
    for letter in message:
        sys.stdout.write(letter)
        sys.stdout.flush()
        time.sleep(0.05)
    
    pause()

def admin_menu():
    decrypt_end_of_day_report()

    while True:
        clear_screen()
        print_header("Welcome to SPAM - (Admin Menu)")

        print("1. Create Key-pair on Server.")
        print("2. Create Key-pair on Client.")
        print("3. Download Menu.")
        print("4. Upload Report.")
        print("5. Shutdown Server.")
        print("6. Logout.")
        
        instructions = "\nOnly accepts digits."
        instructions += "\nEnter '0' to exit."
        instructions += "\n\nOption -> "

        try:
            option = int(input(instructions).strip())

            if option == 0: 
                logout()
                return "break"
            
            elif option == 1: 
                create_private_and_public_key_on_server_and_download_server_public_key()
                return "break"

            elif option == 2: 
                clear_screen()
                client_side_security.create_private_and_public_key()
                return_code = locally_encrypt_client_private_key_file()

                client_public_key_hash = client_side_security.get_file_hash(client_side_security.public_key_file)
                upload_data(command_to_server.upload_client_public_key_hash, client_public_key_hash)
                print(f"\n** Uploaded MD5 of Client's public key file: {client_public_key_hash}")

                upload_file(command_to_server.upload_client_public_key_file, client_side_security.public_key_file)
                print("\n** Uploading client's public key file to the server.")

                pause()
                
                if return_code == "break":
                    logout()
                    return "break"
                
            elif option == 3: download_menu_and_perform_integrity_check()
            elif option == 4: upload_end_of_day_report_and_perform_integrity_check()
            elif option == 5: shutdown_server()
            elif option == 6: break

        except ValueError:
            print("\nOnly accepts digits.")
            short_pause()

def user_menu():
    download_menu_and_load_food_data_into_nested_dict()
    client_data.get_todays_menu()

    decrypt_end_of_day_report()
    
    while True:
        clear_screen()
        print_header("Welcome to SPAM - (User Menu)")

        print("1. Today's Menu.")
        print("2. Buy Food.")
        print("3. Confirm Purchase.")
        print("4. About us.")
        print("5. Logout.")

        instructions = "\nOnly accepts digits."
        instructions += "\nEnter '0' to exit."
        instructions += "\n\nOption -> "

        try:
            option = int(input(instructions).strip())

            if option == 0: 
                logout()
                return "break"

            elif option == 1: 
                display_todays_menu()

            elif option == 2:
                search_food()
                
            elif option == 3:
                if len(client_data.food_cart) > 0: list_order()
                else: 
                    print("\nThere are no items in the cart.")
                    pause()

            elif option == 4: about_us()
            elif option == 5: break

        except ValueError:
            print("\nOnly accepts digits.")
            short_pause()

def logout():
    private_key_file_exist = path.exists(client_side_security.private_key_file)

    if private_key_file_exist:
        remove(client_side_security.private_key_file)
        print(f"\n** Removed -> {client_side_security.private_key_file}")
        short_pause()  
    
    end_of_day_report_file_exist = path.exists(client_data.end_of_day_report_file)

    if end_of_day_report_file_exist:
        client_public_key = RSA.import_key(open(client_side_security.public_key_file).read())
        client_side_security.rsa_encrypt_file(client_data.end_of_day_report_file, client_data.encrypted_end_of_day_report_file, client_public_key)
        remove(client_data.end_of_day_report_file)

        print(f"\n** Encrypt end of day report with client public key file to protect data after logging out:\n{client_data.encrypted_end_of_day_report_file}")
        pause()

def login():
    while True:
        clear_screen()
        print_header("Login")

        username = input("** Username -> ").lower().strip()
        password = input("** Password -> ").strip()

        # To get its hash equivalent. If password is correct, hash will match.
        hashed_password = hashlib.md5(password.encode()).hexdigest() 

        username_and_password = tuple()
        username_and_password = (username, hashed_password)
        username_and_password = str(username_and_password).encode()

        server_public_key = RSA.import_key(open(client_side_security.server_public_key_file).read())
        username_and_password_ciphertext = client_side_security.rsa_encrypt(username_and_password, server_public_key)
        print(f"\n** Encrypted username and password to:\n{b64encode(username_and_password_ciphertext).decode()}")

        client_private_key = RSA.import_key(open(client_side_security.private_key_file).read())
        authentication_details_signature = b64encode(client_side_security.sign(username_and_password_ciphertext, client_private_key))
        print(f"\n** Authentication details signed with private key:\n{authentication_details_signature.decode()}")

        upload_signature(command_to_server.upload_authentication_details_signature, authentication_details_signature)
        print("\n** Uploaded authentication details signature to the server.")

        username_and_password_ciphertext = b64encode(username_and_password_ciphertext)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((connect_to_server.ip_address, connect_to_server.port))
            client_socket.sendall((command_to_server.user_login.encode()))

            short_pause()
            client_socket.send(username_and_password_ciphertext)
            print("\n** Sending encrypted username and password to server.")
            print("\n** Waiting for a reply from the server.")

            authentication_reply_encrypted = client_socket.recv(4096).decode()
            print(f"\n** Authentication reply from server:\n{authentication_reply_encrypted}")
            authentication_reply_encrypted = b64decode(authentication_reply_encrypted)

            authentication_details_signature = client_socket.recv(4096).decode()
            print(f"\n** Authentication details signature from server:\n{authentication_details_signature}")
            
        verification_results = client_side_security.verify(authentication_reply_encrypted, authentication_details_signature, server_public_key)
        print(f"\n** Verification results:\n{verification_results}")

        if verification_results == True:
            print("\n** Verified that authentication details are from server. Will proceed with decrpyting authentication details.")

            client_private_key = RSA.import_key(open(client_side_security.private_key_file).read())
            authentication_reply = client_side_security.rsa_decrypt(authentication_reply_encrypted, client_private_key)
            print(f"\n** Decrypting authentication reply:\n{authentication_reply}")

            pause()

            if authentication_reply == "admin_yes": 
                return_code = admin_menu()
                if return_code == "break": break
            
            elif authentication_reply == "yes": 
                return_code = user_menu()
                if return_code == "break": break

        else:
            print("\n[!] Authentication details has been tampered. Will skip processing login this time.")
            pause()

def initialise():
    clear_screen()
    return_code = download_server_public_key()

    if return_code == "pass":
        client_public_key_hash = client_side_security.get_file_hash(client_side_security.public_key_file)
        upload_data(command_to_server.upload_client_public_key_hash, client_public_key_hash)
        print(f"\n** Uploaded MD5 of Client's public key file: {client_public_key_hash}")

        upload_file(command_to_server.upload_client_public_key_file, client_side_security.public_key_file)
        print("\n** Uploading client's public key file to the server.")
        pause()

        while True:
            clear_screen()
            print_header("Client - Decrypt private key file")

            password = input("** Input password to decrypt private key file -> ").strip()
            client_side_security.aes_decrypt_file(password, client_side_security.private_key_file_encrypted, client_side_security.private_key_file)

            decrypting_result = check_error_after_decryption(client_side_security.private_key_file)

            if decrypting_result == "ok": login()
            else: 
                print("\nWrong password.")
                short_pause()

    else:
        print("[!] Server public key file is corrupted.")
        pause()

connect_to_server = Connection("127.0.0.1", 4444)
command_to_server = Command()
client_data = Data()
client_side_security = Security()

initialise()