import socket
import threading
import json

from .key_exchange import (
    load_parameters,
    generate_dh_keypair,
    load_peer_public_key,
    generate_shared_secret,
)
from .encryption import derive_key, encrypt_message, decrypt_message


class SecureClient:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 5555
        self.socket = None
        self.session_key = None
        self.username = None
        self.on_message = None

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        # DH Handshake
        param_bytes = self.socket.recv(4096)
        parameters = load_parameters(param_bytes)

        private_key, public_bytes = generate_dh_keypair(parameters)
        self.socket.send(public_bytes)

        server_public_bytes = self.socket.recv(4096)
        server_public_key = load_peer_public_key(server_public_bytes)

        shared_secret = generate_shared_secret(private_key, server_public_key)
        self.session_key = derive_key(shared_secret)

    def authenticate(self, action, username, password):
        self.username = username

        auth_message = {
            "type": "auth",
            "action": action,
            "username": username,
            "password": password
        }

        encrypted = encrypt_message(self.session_key, json.dumps(auth_message))
        self.socket.send(encrypted)

        response_data = self.socket.recv(8192)
        decrypted = decrypt_message(self.session_key, response_data)
        response = json.loads(decrypted)

        if response["status"] == "success":
            threading.Thread(target=self.receive_loop, daemon=True).start()
            return True, ""
        else:
            return False, response.get("message", "")

    def send_message(self, payload):
        encrypted = encrypt_message(self.session_key, json.dumps(payload))
        self.socket.send(encrypted)

    def receive_loop(self):
        while True:
            try:
                encrypted_data = self.socket.recv(8192)
                if not encrypted_data:
                    break

                decrypted = decrypt_message(self.session_key, encrypted_data)
                message = json.loads(decrypted)

                if self.on_message:
                    self.on_message(message)

            except:
                break