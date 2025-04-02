from cryptography.fernet import Fernet
import os

key_file = "encryption_key.key"

#Ensure the encryption key is generated once and reused
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, "wb") as keyfile:
        keyfile.write(key)
else:
    with open(key_file, "rb") as keyfile:
        key = keyfile.read()

encryptor = Fernet(key)

def encrypt_data(data): #Encrypts the data and function is called before adding data to the database
    return encryptor.encrypt(data.encode()).decode()

def decrypt_data(data): #Decrypts data and function is called when retrieving data from the database
    return encryptor.decrypt(data.encode()).decode()
