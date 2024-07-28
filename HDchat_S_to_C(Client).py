import os
import socket
import threading
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import asyncio
import websockets
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import base64
os.environ['SECRET_KEY'] = '0123456789abcdef'


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes


def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


def receive_messages(sock, key):
    while True:
        try:
            encrypted_message = sock.recv(2048)
            if encrypted_message:
                decrypted_message = decrypt_message(encrypted_message, key)
                message_data = json.loads(decrypted_message)
                sender = message_data.get('sender', 'Unknown')
                text = message_data.get('message', '')
                if 'filename' in message_data:
                    file_size = int(message_data['file_size'])
                    file_data = b""
                    while len(file_data) < file_size:
                        packet = sock.recv(1024)
                        if not packet:
                            break
                        file_data += packet
                    with open(message_data['filename'], 'wb') as f:
                        f.write(file_data)
                    print(f"Received file {message_data['filename']} from {sender}")
                else:
                    print(f"{sender}: {text}")
            else:
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def register(sock, key):
    username = input("Choose a username: ")
    password = input("Choose a password: ")
    data = {
        "action": "register",
        "username": username,
        "password": password
    }
    encrypted_data = encrypt_message(json.dumps(data), key)
    sock.send(encrypted_data)
    response = decrypt_message(sock.recv(2048), key)
    print(response)


def login(sock, key):
    global username
    username = input("Username: ")
    password = input("Password: ")
    data = {
        "action": "login",
        "username": username,
        "password": password
    }
    encrypted_data = encrypt_message(json.dumps(data), key)
    sock.send(encrypted_data)
    response = json.loads(decrypt_message(sock.recv(2048), key))
    print(response['status'])
    if response['status'] == "Login successful":
        print("Registered users:")
        for user in response['users']:
            print(user)
    return response['status'] == "Login successful"


def send_file(sock, key):
    filepath = input("Enter the path of the file to send: ")
    receiver = input("Enter receiver (or 'all' for public message): ")
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)
    with open(filepath, 'rb') as f:
        file_data = f.read()
    data = {
        "action": "send_file",
        "receiver": receiver,
        "filename": filename,
        "file_size": file_size,
        "sender": username
    }
    try:
        encrypted_data = encrypt_message(json.dumps(data), key)
        sock.send(encrypted_data)
        sock.send(file_data)
    except BrokenPipeError:
        print("Connection lost while sending file.")


def main():
    global username
    secret_key = os.environ.get('SECRET_KEY', '0123456789abcdef').encode()  # Ensure this key is 16 bytes long
    server_ip = input("Enter server IP: ")
    server_port = 5555

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, server_port))

    while True:
        choice = input("Do you want to (1) Login or (2) Register? ")
        if choice == '1':
            if login(sock, secret_key):
                break
        elif choice == '2':
            register(sock, secret_key)
        else:
            print("Invalid choice. Please choose again.")

    threading.Thread(target=receive_messages, args=(sock, secret_key)).start()

    while True:
        action = input("Do you want to (1) Send a Message or (2) Send a File? ")
        if action == '1':
            receiver = input("Enter receiver (or 'all' for public message): ")
            message = input("Enter your message: ")
            data = {
                "action": "message",
                "receiver": receiver,
                "message": message,
                "sender": username
            }
            try:
                encrypted_data = encrypt_message(json.dumps(data), secret_key)
                sock.send(encrypted_data)
            except BrokenPipeError:
                print("Connection lost while sending message.")
        elif action == '2':
            send_file(sock, secret_key)
        else:
            print("Invalid action. Please choose again.")


if __name__ == "__main__":
    main()

# Load or generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def load_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_message(public_key, message):
    return base64.b64encode(public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA1(), label=None)
    ))


def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA1(), label=None)
    )


private_key, public_key = generate_keys()


async def handle_server(websocket, path):
    async for message in websocket:
        data = json.loads(message)
        tag = data.get("tag")

        if tag == "message":
            sender = data.get("from")
            recipient = data.get("to")
            info = decrypt_message(private_key, data.get("info").encode()).decode()

            print(f"Message from {sender} to {recipient}: {info}")

            # Handle message accordingly

        elif tag == "presence":
            print("Presence update received")
            # Handle presence update

        elif tag == "check":
            response = {"tag": "checked"}
            await websocket.send(json.dumps(response))

        elif tag == "attendance":
            print("Attendance check received")
            # Handle attendance

        # Add additional cases as necessary


async def server_to_server():
    server = await websockets.serve(handle_server, "localhost", 5555)
    await server.wait_closed()


async def send_message(websocket, recipient, message):
    encrypted_info = encrypt_message(public_key, message.encode())
    data = {
        "tag": "message",
        "from": "server1",
        "to": recipient,
        "info": encrypted_info.decode()
    }
    await websocket.send(json.dumps(data))


async def main():
    async with websockets.connect("ws://<other_server_ip>:5555") as websocket:
        await send_message(websocket, "server2", "Hello, Server 2!")
        # Add other interaction logic


# Run the server-to-server communication
loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.gather(server_to_server(), main()))