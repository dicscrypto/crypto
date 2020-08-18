import datetime
import sys
import socket
import time
import hashlib
import traceback
import sqlite3

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from string import Template
from calendar import day_name
from datetime import date

from os import getcwd, system, path, remove
from base64 import b64encode, b64decode
from glob import glob

from Crypto.Util.Padding import pad, unpad
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
    def __init__(self):
        self.menu_file = getcwd() + "\\menu.txt"
        self.login_file = getcwd() + "\\creds.db" 
        self.end_of_day_report_base = getcwd() + "\\day_end_" 
        self.encrypted_end_of_day_report_file_base = getcwd() + "\\day_end_encrypted_" 

        self.md5_of_menu_file = "" 
        self.encrypted_end_of_day_report_signature = ""
        self.authentication_details_signature = ""

        self.email_address = ""
        self.email_password = ""

class Command:
    def __init__(self):
        # Various commands which will be used to process commands that was sent from client.
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
        self.private_key_file = getcwd() + "\\server_private.pem" 
        self.private_key_file_encrypted = getcwd() + "\\server_private.aes"
        self.public_key_file = getcwd() + "\\server_public.pem" 
        self.client_public_key_file = getcwd() + "\\client_public.pem"

        self.md5_of_public_key_file = ""
        self.md5_of_client_public_key_file = ""

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

        print(f"[I] Done creating Private Key:\n{self.private_key_file}")

        with open(self.public_key_file, 'wb') as public_key_file: 
            public_key_file.write(public_key)

        print(f"[I] Done creating Public Key:\n{self.public_key_file}")

    def aes_encrypt(self, plaintext, password):
        #private_key = hashlib.sha256(password.encode()).digest() # For local use.
        private_key = password  # For remote use.
        padded_plaintext = pad(plaintext, AES.block_size)
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

        print(f"[+] Encrypted -> \"{file_to_be_encrypted}\" TO \"{destination_file}\" ")

        remove(file_to_be_encrypted) # Remove the original plaintext file from disk.

        print(f"[+] Removed original file: \"{file_to_be_encrypted}\"")

    def aes_decrypt(self, ciphertext, password):
        private_key = hashlib.sha256(password.encode()).digest()
        ciphertext = b64decode(ciphertext) # Decode to binary.
        iv = ciphertext[:16] # First 16 bytes.
        
        cipher_aes = AES.new(private_key, AES.MODE_CBC, iv)

        plaintext = cipher_aes.decrypt(ciphertext[16:]) # After 16 bytes.
        plaintext = unpad(plaintext, AES.block_size)

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

def authenticate_user(username, password):
    login_file_exists = path.exists(server_data.login_file)

    if login_file_exists:
        try:
            sqlite_connection = sqlite3.connect(server_data.login_file)
            print("** Connection to DB successful.")

            query = f"SELECT * FROM creds WHERE "
            query += f"username = \"{username}\" AND password = \"{password}\" LIMIT 1"

            cursor = sqlite_connection.cursor()
            cursor.execute(query)

            result = cursor.fetchall()
            return result
        
        except sqlite3.Error as error:
            print(f"[!] Error: {error}")

        finally:
            # If sql connection exist, close the sql connection.
            if (sqlite_connection):
                sqlite_connection.close()
                print("** Connection to DB closed.")

    else:
        print("[!] Unable to find DB file.")
        sys.exit(1)

def load_email_credentials(filename):
    with open(filename, "r") as email_credential_file:
        creds = email_credential_file.readline()
        creds = creds.split()

        server_data.email_address = creds[0]
        server_data.email_password = creds[1]

def get_contacts(filename):
    names = list()
    emails = list()

    with open(filename, "r") as contacts_file:
        for individual_contact in contacts_file:
            names.append(individual_contact.split()[0])
            emails.append(individual_contact.split()[1])

    return names, emails

def read_template(filename):
    with open(filename, "r") as template_file:
        template_file_content = template_file.read()

    return Template(template_file_content)

def send_email(end_of_day_report_filename, current_day, current_time):
    load_email_credentials("email_credentials.txt")
    names, emails = get_contacts("contacts.txt")
    message_template = read_template("message.txt")

    try: 
        smtp_connection = smtplib.SMTP(host = "smtp.office365.com", port = 587)
        smtp_connection.starttls()
        smtp_connection.login(server_data.email_address, server_data.email_password)

        for name, email in zip(names, emails):
            email_message = MIMEMultipart()

            message_to_be_sent = message_template.substitute(PERSON_NAME = name.title(), REPORT_NAME = end_of_day_report_filename)

            print("\n" + "#" * 64)
            print(f"\n** Sent email: \n{message_to_be_sent}")
            print("\n" + "#" * 64)

            email_message['From'] = server_data.email_address
            email_message['To'] = email
            email_message['Subject'] = f"Report has been uploaded to server @{current_day} - {current_time}"
            email_message.attach(MIMEText(message_to_be_sent, 'plain'))

            smtp_connection.send_message(email_message)
            del email_message

            short_pause()

        smtp_connection.quit()

    except Exception as error:
        print(f"[!] Error while sending email: {error}")
        pass

def process_connection(connection, ip_address): 
    user_command = connection.recv(4096).decode()

    if user_command == command_from_client.download_menu_hash:
        server_data.md5_of_menu_file = server_side_security.get_file_hash(server_data.menu_file)
        connection.sendall(server_data.md5_of_menu_file.encode())

        print("** Completed: [Sending] default menu hash.")
        return

    elif user_command == command_from_client.download_menu:
        send_file(connection, server_data.menu_file)

        print("** Completed: [Sending] default menu.")
        return

    elif user_command == command_from_client.download_server_public_key_file_hash:
        server_side_security.md5_of_public_key_file = server_side_security.get_file_hash(server_side_security.public_key_file)
        connection.sendall(server_side_security.md5_of_public_key_file.encode())

        print("** Completed: [Sending] public key file hash.")
        return

    elif user_command == command_from_client.download_server_public_key_file:
        send_file(connection, server_side_security.public_key_file)

        print("** Completed: [Sending] public key file.")
        return

    elif user_command == command_from_client.upload_client_public_key_hash:
        client_public_key_hash = connection.recv(4096).decode()
        server_side_security.md5_of_client_public_key_file = client_public_key_hash

        print(f"[+] Received MD5 of Client's public key file: {client_public_key_hash}")
        return

    elif user_command == command_from_client.upload_client_public_key_file:
        download_file(connection, server_side_security.client_public_key_file)

        print(f"[+] Saving client's public key file as:\n{server_side_security.client_public_key_file}")
       
    elif user_command == command_from_client.upload_end_of_day_report:
        end_of_day_report_filename = server_data.encrypted_end_of_day_report_file_base + ip_address + " - " + get_formatted_date_and_time() + ".txt"

        local_md5_of_client_public_key_file = server_side_security.get_file_hash(server_side_security.client_public_key_file)
        print(f"** Client Public Key File MD5: {local_md5_of_client_public_key_file}")
        print(f"** Downloaded Client Public Key File MD5: {server_side_security.md5_of_client_public_key_file}")
        
        if local_md5_of_client_public_key_file == server_side_security.md5_of_client_public_key_file: print("[+] Hash check passed: No tampering detected on client's public key file.")
        else: print("[!] Hash check failed: Tampering detected on client's public key file.")

        client_public_key = RSA.import_key(open(server_side_security.client_public_key_file).read())
        server_private_key = RSA.import_key(open(server_side_security.private_key_file).read())

        end_of_block = False
        data_corrupted = False

        count = 0 
        data_list = list()

        while not end_of_block:
            signature_and_encrypted_block = connection.recv(4096)

            if signature_and_encrypted_block != b'':
                encrypted_block = signature_and_encrypted_block[0:256]
                signature_block = signature_and_encrypted_block[256:]
                
                print(f"\n** BLOCK {count}. {len(signature_block)} Signature:\n{b64encode(signature_block).decode()}")

                verification_result = server_side_security.verify(encrypted_block, b64encode(signature_block), client_public_key)

                if verification_result == True:
                    decrypted_block = server_side_security.rsa_decrypt(encrypted_block, server_private_key)
                    print(f"\n** BLOCK {count}. {len(decrypted_block)} Decrypted:\n{decrypted_block}")

                    count += 1
                    data_list.append(decrypted_block)

                    connection.send(b"ok")

                else:
                    connection.send(b"corrupted")
                    print(f"[!] Detected integrity issues on BLOCK {count}.")

                    data_corrupted = True
                    break
                    
            else:
                end_of_block = True

        with open(end_of_day_report_filename, 'w', newline = '\n') as eod:
            if data_corrupted == False:
                for data in data_list:
                    eod.write(data)

                print(f"\n** Successfully wrote decrypted data to:\n{end_of_day_report_filename}")

        current_day = day_name[date.today().weekday()]
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        send_email(end_of_day_report_filename, current_day, current_time)

        return

    elif user_command == command_from_client.upload_end_of_day_report_signature:
        end_of_day_report_signature = connection.recv(4096).decode()
        server_data.encrypted_end_of_day_report_signature = end_of_day_report_signature

        print(f"[+] Received end of day report signature:\n{end_of_day_report_signature}")
        return

    elif user_command == command_from_client.upload_authentication_details_signature:
        authentication_details_signature = connection.recv(4096)
        server_data.authentication_details_signature = authentication_details_signature

        print(f"[+] Received authentication details signature:\n{authentication_details_signature}")
        return

    elif user_command == command_from_client.create_private_and_public_key:
        server_side_security.create_private_and_public_key()
        
        connection.send(b"ok")
        return

    elif user_command == command_from_client.remotely_encrypt_server_private_key_file:
        password = connection.recv(4096)
        server_side_security.aes_encrypt_file(password, server_side_security.private_key_file, server_side_security.private_key_file_encrypted)

        print("** Completed: [Encrypting] server private key file.")
        print("[!] Please restart the server application again.")

        connection.send(b"private key encryption ok")
        return "restart_server"

    elif user_command == command_from_client.shutdown_server:
        print("[!] Shutdown signal received. Server shutting down.")
        short_pause()

        encrypt_all_report()
        encrypt_email_creds_file()

        short_pause()

        remove(server_side_security.private_key_file)
        print(f"[!] Removed {server_side_security.private_key_file}")
        short_pause()

        return "shutdown_server"

    elif user_command == command_from_client.user_login:
        encrypted_username_and_password = connection.recv(4096).decode()

        print(f"** Received encrypted username and password:\n{encrypted_username_and_password}")
        encrypted_username_and_password = b64decode(encrypted_username_and_password)
      
        local_md5_of_client_public_key_file = server_side_security.get_file_hash(server_side_security.client_public_key_file)
        print(f"** Client Public Key File MD5: {local_md5_of_client_public_key_file}")
        print(f"** Downloaded Client Public Key File MD5: {server_side_security.md5_of_client_public_key_file}")

        if local_md5_of_client_public_key_file == server_side_security.md5_of_client_public_key_file: print("[+] Hash check passed: No tampering detected on client's public key file.")
        else: print("[!] Hash check failed: Tampering detected on client's public key file.")

        client_public_key = RSA.import_key(open(server_side_security.client_public_key_file).read())
        verification_result = server_side_security.verify(encrypted_username_and_password, server_data.authentication_details_signature, client_public_key)
        print(f"[I] Signature verification results: {verification_result}")

        if verification_result == True:
            print("** Verified that authentication details are from client. Will proceed with decrypting username and password.")
            
            private_key = RSA.import_key(open(server_side_security.private_key_file).read())
            username_and_password = server_side_security.rsa_decrypt(encrypted_username_and_password, private_key)
            username_and_password = eval(username_and_password) # Convert from string to tuple.

            username = username_and_password[0]
            password = username_and_password[1]

            authentication_results = authenticate_user(username, password)
            
            if len(authentication_results) > 0: 
                authentication_results = authentication_results[0]
                is_admin = authentication_results[2]

                if is_admin == "yes": authentication_successful = "admin_yes"
                else: authentication_successful = "yes"

            else: authentication_successful = "no"

            client_public_key = RSA.import_key(open(server_side_security.client_public_key_file).read())
            authentication_successful_encrypted = b64encode(server_side_security.rsa_encrypt(authentication_successful.encode(), client_public_key))
            connection.send(authentication_successful_encrypted)
            print(f"** Sending authentication results back to the client:\n{authentication_successful_encrypted.decode()}")

            server_private_key = RSA.import_key(open(server_side_security.private_key_file).read())
            authentication_successful_encrypted = b64decode(authentication_successful_encrypted)
            authentication_successful_encrypted_signature = b64encode(server_side_security.sign(authentication_successful_encrypted, server_private_key))
            print(f"** Authentication details signature:\n{authentication_successful_encrypted_signature.decode()}")

            connection.send(authentication_successful_encrypted_signature)
            print(f"** Completed: [Sending] authentication details signature to the client.")

        else:
            authentication_successful = "no"
            client_public_key = RSA.import_key(open(server_side_security.client_public_key_file).read())
            authentication_successful_encrypted = b64encode(server_side_security.rsa_encrypt(authentication_successful.encode(), client_public_key))
            connection.send(authentication_successful_encrypted)
            print("[!] Authentication details has been tampered. Will skip processing login this time.")

        return

def connection_handler(connection, ip_address, port):
    return_code = process_connection(connection, ip_address)
    connection.close()

    connection_terminated_time = datetime.datetime.now().strftime("%H:%M:%S")            
    print(f"[-] Connection Terminated -> Time: {connection_terminated_time} IP: {ip_address} PORT: {port}")

    if return_code != "": return return_code
    else: return

def check_error_after_decryption(destination_file):
    with open(destination_file, "rb") as dest_file:
        data = dest_file.read()

    if b"-----BEGIN RSA PRIVATE KEY-----" in data: return "ok" # If this string is present, most likely decryption is successful.
    else: return "failed"

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
                print(f"[+] Connection Made -> Time: {connection_made_time} IP: {ip_address} PORT: {port}")

                try:
                    return_code = connection_handler(connection, ip_address, port)

                    if return_code == "restart_server": 
                        print("[!] Restart signal received. Server will now restart.")

                        short_pause()
                        break

                    elif return_code == "shutdown_server":
                        return return_code

                except Exception as error:
                    print(f"[!] Error occured : {error}")
                    traceback.print_exc()

        except: pass
        return

def animation(message):
    for letter in message:
        sys.stdout.write(letter)
        sys.stdout.flush()
        time.sleep(0.05)

def decrypt_email_creds_file():
    clear_screen()
    server_private_key = RSA.import_key(open(server_side_security.private_key_file).read())
    
    encrypted_email_credentials_file = getcwd() + "\\email_credentials.rsa"
    encrypted_email_credentials_file_exists = path.exists(encrypted_email_credentials_file)

    if encrypted_email_credentials_file_exists:
        with open(encrypted_email_credentials_file, "rb") as ef:
            encrypted_block = ef.read(256)
            plaintext_block_list = list()
            count = 0

            while encrypted_block!= b"":
                decrypted_block = server_side_security.rsa_decrypt(encrypted_block, server_private_key)
                print(f"** BLOCK {count}. {len(decrypted_block)} , Decrypted block:\n{decrypted_block}\n")

                plaintext_block_list.append(decrypted_block)
                count += 1

                encrypted_block = ef.read(256)

        decrypted_filename = encrypted_email_credentials_file.split("rsa")[0] + "txt"

        with open(decrypted_filename, "w", newline = "\n") as df:
            for plaintext_block in plaintext_block_list:
                df.write(plaintext_block) 

        print(f"\n** Decrypted:\n{encrypted_email_credentials_file}\n")
        pause()
    
    else:
        print(f"** Unable to locate:\n{encrypted_email_credentials_file}")
        short_pause()
  
def encrypt_email_creds_file():
    clear_screen()
    server_public_key = RSA.import_key(open(server_side_security.public_key_file).read())
    
    email_credentials_file = getcwd() + "\\email_credentials.txt"
    email_credentials_file_exists = path.exists(email_credentials_file)

    if email_credentials_file_exists:
        with open(email_credentials_file, "rb") as plaintext_file:
            plaintext_block = plaintext_file.read(64)
            encrypted_block_list = list()
            count = 0

            while plaintext_block != b"":
                encrypted_block = server_side_security.rsa_encrypt(plaintext_block, server_public_key)
                print(f"\n** BLOCK {count}. {len(encrypted_block)} , Encrypted block:\n{b64encode(encrypted_block).decode()}")

                encrypted_block_list.append(encrypted_block)
                count += 1

                plaintext_block = plaintext_file.read(64)

        encrypted_filename = email_credentials_file.split("txt")[0] + "rsa"

        with open(encrypted_filename, "wb") as ef:
            for encrypted_block in encrypted_block_list:
                ef.write(encrypted_block)

        print(f"\n** Encrypted:\n{email_credentials_file}\n")

        remove(email_credentials_file)

        print(f"\n** Removed:\n{email_credentials_file}")

    else:
        print(f"** Unable to locate:\n{email_credentials_file}")

def encrypt_all_report():
    unencrypted_end_of_day_report_filter = getcwd() + "\\day*.txt"
    list_of_unencrypted_end_of_day_report = glob(unencrypted_end_of_day_report_filter)

    server_public_key = RSA.import_key(open(server_side_security.public_key_file).read())
    encrypted_block_list = list()
    count = 0

    if len(list_of_unencrypted_end_of_day_report) > 0:
        for text_file in list_of_unencrypted_end_of_day_report:
            with open(text_file, "rb") as plaintext_file:
                plaintext_block = plaintext_file.read(64)

                while plaintext_block != b"":
                    encrypted_block = server_side_security.rsa_encrypt(plaintext_block, server_public_key)
                    print(f"\n** BLOCK {count}. {len(encrypted_block)} , Encrypted block:\n{b64encode(encrypted_block).decode()}")

                    encrypted_block_list.append(encrypted_block)
                    count += 1

                    plaintext_block = plaintext_file.read(64)

            encrypted_filename = text_file.split("txt")[0] + "rsa"
            
            with open(encrypted_filename, "wb") as ef:
                for encrypted_block in encrypted_block_list:
                    ef.write(encrypted_block)

                encrypted_block_list.clear()
                print(f"** Encrypted:\n{text_file}\n")

                remove(text_file)
                print(f"** Removed:\n{text_file}\n")

    else:
        print("** No report files to encrypt...")

def decrypt_all_report():
    clear_screen()

    encrypted_end_of_day_report_filter = getcwd() + "\\day*.rsa"
    list_of_encrypted_end_of_day_report = glob(encrypted_end_of_day_report_filter)

    server_private_key = RSA.import_key(open(server_side_security.private_key_file).read())
    plaintext_block_list = list()
    count = 0

    if len(list_of_encrypted_end_of_day_report) > 0:
        for encrypted_file in list_of_encrypted_end_of_day_report:
            with open(encrypted_file, "rb") as ef:
                encrypted_block = ef.read(256)

                while encrypted_block!= b"":
                    decrypted_block = server_side_security.rsa_decrypt(encrypted_block, server_private_key)
                    print(f"** BLOCK {count}. {len(decrypted_block)} , Decrypted block:\n{decrypted_block}\n")

                    plaintext_block_list.append(decrypted_block)
                    count += 1

                    encrypted_block = ef.read(256)

            decrypted_filename = encrypted_file.split("rsa")[0] + "txt"
            
            with open(decrypted_filename, "w", newline = "\n") as df:
                for plaintext_block in plaintext_block_list:
                    df.write(plaintext_block)

                plaintext_block_list.clear()
                print(f"** Decrypted:\n{encrypted_file}\n")

        pause()

    else:
        print("** No report files to decrypt...")
        short_pause()

def initialise():
    while True:
        clear_screen()
        print_header("Server - Decrypt private key file")
        
        animation("** Input password to decrypt private key file: ")
        password = input().strip()
        server_side_security.aes_decrypt_file(password, server_side_security.private_key_file_encrypted, server_side_security.private_key_file)

        decrypting_result = check_error_after_decryption(server_side_security.private_key_file)

        if decrypting_result == "ok": 
            decrypt_all_report()
            decrypt_email_creds_file()

            return_code = start_server()

            if return_code == "shutdown_server": break

        else:
            print("\nWrong password.")
            short_pause()

server_connection = Connection("127.0.0.1", 4444)
command_from_client = Command()
server_data = Data()
server_side_security = Security()

initialise()