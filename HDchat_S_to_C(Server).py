import os
import os
import socket
import threading
import json
import sqlite3
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging
os.environ['SECRET_KEY'] = '0123456789abcdef'

import os
import socket
import threading
import json
import sqlite3
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging

# setting
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize database
def init_db():
    if not os.path.exists('chat_users.db'):
        conn = sqlite3.connect('chat_users.db')
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            salt TEXT
        )
        ''')
        conn.commit()
        conn.close()

# Register new user
def register_user(username, password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt).decode('utf-8')
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', (username, hashed, salt.decode('utf-8')))
    conn.commit()
    conn.close()

# Verify user credentials
def verify_user(username, password):
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return False
    stored_hash, salt = row
    return bcrypt.checkpw(password.encode(), stored_hash.encode('utf-8'))

# Get all registered users
def get_all_users():
    conn = sqlite3.connect('chat_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users')
    users = [row[0] for row in cursor.fetchall()]
    conn.close()
    return users

# Encrypted message
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

# Decrypt message
def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Handle client connections
def handle_client(client_socket, client_address, key):
    global users
    logging.info(f"Handling client {client_address}")
    while True:
        try:
            encrypted_message = client_socket.recv(2048)
            if not encrypted_message:
                break
            logging.debug(f"Encrypted message from {client_address}: {encrypted_message}")
            decrypted_message = decrypt_message(encrypted_message, key)
            message_data = json.loads(decrypted_message)
            action = message_data.get("action")
            if action == "register":
                username = message_data["username"]
                password = message_data["password"]
                if verify_user(username, password):
                    response = "Username already exists."
                else:
                    register_user(username, password)
                    response = "Registration successful."
                client_socket.send(encrypt_message(response, key))
            elif action == "login":
                username = message_data["username"]
                password = message_data["password"]
                if verify_user(username, password):
                    response = {"status": "Login successful", "users": get_all_users()}
                    users[username] = client_socket
                else:
                    response = {"status": "Invalid username or password"}
                client_socket.send(encrypt_message(json.dumps(response), key))
            elif action == "send_file":
                receiver = message_data['receiver']
                filename = message_data['filename']
                file_size = int(message_data['file_size'])
                file_data = b""
                while len(file_data) < file_size:
                    packet = client_socket.recv(1024)
                    if not packet:
                        break
                    file_data += packet
                if receiver in users:
                    users[receiver].send(encrypt_message(json.dumps(message_data), key))
                    users[receiver].send(file_data)
                else:
                    client_socket.send(encrypt_message(json.dumps({"error": "User not found"}), key))
            elif action == "message":
                receiver = message_data['receiver']
                sender = [user for user, sock in users.items() if sock == client_socket][0]
                message_data['sender'] = sender
                if receiver == 'all':
                    broadcast(json.dumps(message_data), client_socket, key)
                else:
                    send_private_message(receiver, json.dumps(message_data), client_socket, key)
        except Exception as e:
            logging.error(f"Error handling message from {client_address}: {e}")
            break
    client_socket.close()
    users = {user: sock for user, sock in users.items() if sock != client_socket}
    logging.info(f"Client {client_address} disconnected")

# Broadcast
def broadcast(message, sender_socket, key):
    encrypted_message = encrypt_message(message, key)
    for client in clients:
        if client != sender_socket:
            try:
                client.send(encrypted_message)
            except Exception as e:
                logging.error(f"Error sending message: {e}")
                client.close()
                clients.remove(client)

# Send private message to specified client
def send_private_message(receiver, message, sender_socket, key):
    encrypted_message = encrypt_message(message, key)
    if receiver in users:
        users[receiver].send(encrypted_message)
    else:
        sender_socket.send(encrypt_message(json.dumps({"error": "User not found"}), key))

# Start the server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 5555))
    server_socket.listen(5)
    logging.info("Server started on port 5555")
    secret_key = os.environ.get('SECRET_KEY', '0123456789abcdef').encode()  # Ensure this key is 16 bytes long
    while True:
        client_socket, client_address = server_socket.accept()
        logging.info(f"Client {client_address} connected")
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, client_address, secret_key)).start()

if __name__ == "__main__":
    init_db()
    clients = []
    users = {}
    start_server()