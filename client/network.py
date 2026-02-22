import socket
import json
import threading
import base64
import os

from .key_exchange import (
    load_parameters,
    generate_dh_keypair,
    load_peer_public_key,
    generate_shared_secret,
)

from .encryption import derive_key, encrypt_message, decrypt_message


class SecureClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.session_key = None
        self.username = None
        self.running = False
        self.on_message = None
        self.on_user_list = None

    # -------------------------
    # Connect + Handshake
    # -------------------------
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        param_bytes = self.socket.recv(4096)
        parameters = load_parameters(param_bytes)

        private_key, public_bytes = generate_dh_keypair(parameters)
        self.socket.send(public_bytes)

        server_public_bytes = self.socket.recv(4096)
        server_public_key = load_peer_public_key(server_public_bytes)

        shared_secret = generate_shared_secret(private_key, server_public_key)
        self.session_key = derive_key(shared_secret)

        self.running = True

        thread = threading.Thread(target=self.receive_loop)
        thread.daemon = True
        thread.start()

    # -------------------------
    # Authentication
    # -------------------------
    def authenticate(self, action, username, password):
        request = {
            "action": action,
            "username": username,
            "password": password
        }

        encrypted = encrypt_message(self.session_key, json.dumps(request))
        self.socket.send(encrypted)

        response_data = self.socket.recv(8192)
        decrypted = decrypt_message(self.session_key, response_data)
        response = json.loads(decrypted)

        if response["status"] == "success":
            self.username = username
            return True, response.get("message", "")
        else:
            return False, response.get("message", "Authentication failed")

    # -------------------------
    # Send Chat Message
    # -------------------------
    def send_message(self, message):
        encrypted = encrypt_message(self.session_key, message)
        self.socket.send(encrypted)

        self.save_local_message(f"You: {message}")
    # -------------------------
    # Receive Loop
    # -------------------------
    def receive_loop(self):
        while self.running:
            try:
                data = self.socket.recv(8192)
                if not data:
                    break

                decrypted = decrypt_message(self.session_key, data)

                # Try JSON parsing (user list or file)
                try:
                    parsed = json.loads(decrypted)

                    # Online users update
                    if parsed.get("type") == "user_list":
                        if self.on_user_list:
                            self.on_user_list(parsed["users"])
                        continue

                    # File transfer
                    if parsed.get("type") == "file":
                        if self.on_message:
                            self.on_message(
                                f"[FILE] {parsed['from']} sent {parsed['filename']}"
                            )
                        self.save_file(parsed["filename"], parsed["data"])
                        continue

                except:
                    pass

                # Normal chat message
                if self.on_message:
                    self.on_message(decrypted)
                    self.save_local_message(decrypted)

            except:
                break

        self.running = False
        self.socket.close()

    def save_local_message(self, message):
            if not self.username:
                return

            os.makedirs("history", exist_ok=True)

            encrypted = encrypt_message(self.session_key, message)

            with open(f"history/{self.username}.bin", "ab") as f:
                f.write(encrypted + b"\n")

    # -------------------------
    # Save Received File
    # -------------------------
    def save_file(self, filename, encoded_data):
        data = base64.b64decode(encoded_data)
        with open(f"received_{filename}", "wb") as f:
            f.write(data)
