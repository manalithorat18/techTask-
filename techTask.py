import os
import json
import getpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitive import hashes
from cryptography.hazmat.primitive.kdf.pdkdf2 import PBKDF2HMAC
import secrets
import string

MASTER_PASSWORD_FILE = ".master_password"
PASSWORD_STORE_FILE = ".password_store.json"
SALT = b"salt_"

# encryption key set up
def generate_key(master_password):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = SALT,
        iterations = 100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# Fernet instance set up
def get_fernet(key):
    return Fernet(key)

# data encryption
def encrypt(data, fernet):
    return fernet.encrypt(data.encode())

# data decryption
def decrypt(data, fernet):
    return fernet.decrypt(data).decode()

#strong password generation
def password_strength_checkup(password):
    if len(password) < 8:
        return 'weak'
    if not any(char.isdigit() for char in password):
        return 'weak'
    if not any(char.isupper() for char in password):
        return 'weak'
    if not any(char.islower() for char in password):
        return 'weak'
    if not any(char in string.punctuation for char in password):
        return 'medium'
    return 'strong'

# Load passwords from file
def load_passwords():
    if not os.path.exists(PASSWORD_STORE_FILE):
        return []
    with open(PASSWORD_STORE_FILE, "r") as f:
        return json.load(f)

# Save passwords to file
def save_passwords(passwords):
    with open(PASSWORD_STORE_FILE, "w") as f:
        json.dump(passwords, f)

#password addition
def add_password(fernet, master_password, passwords):
    account_name = input("Enter account name: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    strength = password_strength_checkup(password)
    print(f"Password Strength: {strength}")
    encrypted_password = encrypt(password, fernet)
    data = {"account_name" : account_name, "username" :username, "encrypted_password" :encrypted_password.decode()}
    for existing_password in passwords:
        if existing_password['account_name'] == account_name:
            print("Account name already exists. please choose a different name.")
            return
        
    passwords.append(data)  
    save_passwords(passwords) 

# view password
def view_password(fernet, master_password, passwords):
    for password in passwords:
        print(f"Account Name: {password["account_name"]}")
        print(f"Username: {password['username']}")
        print(" ")

# reveal password
def reveal_password(fernet, master_password, passwords):
    account_name = input("Enter account name: ")
    for password in passwords:
        if password["account_name"] == account_name:
            print(f"Password: {decrypt(save_passwords['encrypted_password'].encode(), fernet)}")
            return
    print("Account not found")

# delete password
def delete_password(fernet, master_password, passwords):
    account_name = input("Enter account name: ")
    for i, password in enumerate(passwords):
        if password["account_name"] == account_name:
            del passwords[i]
            save_passwords(passwords)
            print("Password deleted")
            return
    print("Account not found")    
    
# update password
def update_password(fernet, master_password, passwords):
    account_name = input("Enter account name: ")
    for password in passwords:
        if password["account_name"] == account_name:
            password = getpass.getpass("Enter new password: ")
            strength = password_strength_checkup(password) 
            print(f"Password strength: {strength}")
            encrypted_password = encrypt(password, fernet)
            password["encrypted_password"] = encrypted_password.decode()
            save_passwords(passwords)
            print("Password updated")
            return
    print("Password updated")

    # main function
    def main():
        master_password = getpass.getpass("Enter master password: ")
        key = generate_key(master_password)
        fernet = get_fernet(key)
        passwords = load_passwords()

        while True:
            print("1. Add password")
            print("2. View passwords")
            print("3. Reveal password")
            print("4. Delete password")
            print("5. Update password")
            print("6. Quit")

            choice = input("Enter your choice: ")

            if choice == "1":
                add_password(fernet, master_password, passwords)
            elif choice == "2":
                view_password(fernet, master_password, passwords)      
            elif choice == "3":
                reveal_password(fernet, master_password, passwords)      
            elif choice == "4":
                delete_password(fernet, master_password, passwords)      
            elif choice == "5":
                update_password(fernet, master_password, passwords)      
            elif choice == "6":
                 break
            else:
                print("Invalid choice. Please try again,")





