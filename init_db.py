from flask_bcrypt import Bcrypt
import sqlite3
from encryption import encrypt_data #Imports the encrypt_data function from encryption.py

bcrypt = Bcrypt()  #Create a Bcrypt instance

def insert_user(username, password, mobile, address): #Encrypts and inserts a new user into the database
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8") #Sets variables, encrypts data and hashes the password and so it can be inserted into the database
    encrypted_mobile = encrypt_data(mobile)
    encrypted_address = encrypt_data(address)

    cursor.execute("INSERT INTO users (username, password, mobile, address) VALUES (?, ?, ?, ?)",
                   (username, hashed_password, encrypted_mobile, encrypted_address))

    connection.commit()
    connection.close()

#Initialise the database and execute the schema.sql file
connection = sqlite3.connect('database.db')
with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

connection.commit()
connection.close() #Close the connection with the database