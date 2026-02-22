import socket
import threading
import json
from datetime import datetime
import base64
from .key_exchange import (
    get_parameters_bytes,
    load_parameters,
    generate_dh_keypair,
    load_peer_public_key,
    generate_shared_secret,
)

from .encryption import derive_key, decrypt_message, encrypt_message
from .auth import authenticate_user, register_user


HOST = "0.0.0.0"
PORT = 5555

# { socket: {"key": session_key, "username": username} }
clients = {}


def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr}")

    try:
        # -----------------------------
        # 🔐 Diffie-Hellman Handshake
        # -----------------------------
        param_bytes = get_parameters_bytes()
        client_socket.send(param_bytes)

        client_public_bytes = client_socket.recv(4096)
        parameters = load_parameters(param_bytes)

        private_key, server_public_bytes = generate_dh_keypair(parameters)
        client_socket.send(server_public_bytes)

        client_public_key = load_peer_public_key(client_public_bytes)
        shared_secret = generate_shared_secret(private_key, client_public_key)

        session_key = derive_key(shared_secret)

        print(f"[SECURE SESSION ESTABLISHED] {addr}")

        # -----------------------------
        # 🔐 Authentication Phase
        # -----------------------------
        authenticated = False
        username = None

        while not authenticated:
            encrypted_data = client_socket.recv(8192)
            decrypted = decrypt_message(session_key, encrypted_data)

            request = json.loads(decrypted)

            action = request.get("action")
            user = request.get("username")
            pwd = request.get("password")

            if action == "login":
                if authenticate_user(user, pwd):
                    authenticated = True
                    username = user
                    response = {"status": "success"}
                else:
                    response = {"status": "fail"}

            elif action == "register":
                success, msg = register_user(user, pwd)
                response = {
                    "status": "success" if success else "fail",
                    "message": msg
                }

            else:
                response = {"status": "fail", "message": "Invalid action"}

            encrypted_response = encrypt_message(
                session_key, json.dumps(response)
            )
            client_socket.send(encrypted_response)

        # -----------------------------
        # ✅ Only add client AFTER auth
        # -----------------------------
        clients[client_socket] = {
            "key": session_key,
            "username": username
        }

        print(f"[AUTHENTICATED] {username} from {addr}")

        broadcast_system_message(f"{username} joined the chat.")
        send_user_list()

        # -----------------------------
        # 💬 Secure Messaging Loop
        # -----------------------------
        while True:
            encrypted_data = client_socket.recv(8192)
            if not encrypted_data:
                break

            decrypted_message = decrypt_message(session_key, encrypted_data)

            # Try parsing JSON first (file transfer)
            try:
                parsed = json.loads(decrypted_message)

                # -----------------------
                # 📂 FILE TRANSFER
                # -----------------------
                if parsed.get("type") == "file":
                    target = parsed["to"]
                    file_name = parsed["filename"]
                    file_data = parsed["data"]

                    send_private_file(username, target, file_name, file_data)
                    continue

            except:
                pass

            # -----------------------
            # 💬 PRIVATE MESSAGE
            # -----------------------
            if decrypted_message.startswith("/pm"):
                parts = decrypted_message.split(" ", 2)
                if len(parts) >= 3:
                    target_user = parts[1]
                    msg = parts[2]
                    send_private_message(username, target_user, msg)
                continue

            # -----------------------
            # 🌍 PUBLIC MESSAGE
            # -----------------------
            timestamp = datetime.now().strftime("%H:%M")
            formatted = f"[{timestamp}] {username}: {decrypted_message}"
            broadcast_message_raw(formatted, client_socket)

    except Exception as e:
        print(f"[ERROR] {addr} -> {e}")

    finally:
        user = clients.get(client_socket, {}).get("username")

        if user:
            broadcast_system_message(f"{user} left the chat.")

        print(f"[DISCONNECTED] {addr}")

        clients.pop(client_socket, None)
        client_socket.close()

        send_user_list()

def broadcast_message_raw(message, sender_socket):
    for client, data in list(clients.items()):
        if client != sender_socket:
            try:
                encrypted = encrypt_message(data["key"], message)
                client.send(encrypted)
            except:
                client.close()
                clients.pop(client, None)


def send_private_message(sender, target, message):
    from datetime import datetime
    timestamp = datetime.now().strftime("%H:%M")

    formatted = f"[{timestamp}] (Private) {sender}: {message}"

    for client, data in clients.items():
        if data["username"] == target:
            encrypted = encrypt_message(data["key"], formatted)
            client.send(encrypted)
            break


def send_private_file(sender, target, filename, file_data):
    for client, data in clients.items():
        if data["username"] == target:
            message = json.dumps({
                "type": "file",
                "from": sender,
                "filename": filename,
                "data": file_data
            })
            encrypted = encrypt_message(data["key"], message)
            client.send(encrypted)
            break
# -----------------------------------
# 💬 Broadcast Normal Message
# -----------------------------------
def broadcast_message(sender_username, message, sender_socket):
    for client, data in list(clients.items()):
        if client != sender_socket:
            try:
                encrypted = encrypt_message(
                    data["key"],
                    f"{sender_username}: {message}"
                )
                client.send(encrypted)
            except:
                client.close()
                clients.pop(client, None)


# -----------------------------------
# 🔔 Broadcast System Message
# -----------------------------------
def broadcast_system_message(message):
    for client, data in list(clients.items()):
        try:
            encrypted = encrypt_message(
                data["key"],
                f"[SYSTEM] {message}"
            )
            client.send(encrypted)
        except:
            client.close()
            clients.pop(client, None)


# -----------------------------------
# 👥 Send Online User List
# -----------------------------------
def send_user_list():
    user_list = [
        data["username"] for data in clients.values()
    ]

    message = json.dumps({
        "type": "user_list",
        "users": user_list
    })

    for client, data in list(clients.items()):
        try:
            encrypted = encrypt_message(data["key"], message)
            client.send(encrypted)
        except:
            client.close()
            clients.pop(client, None)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, addr)
        )
        thread.start()