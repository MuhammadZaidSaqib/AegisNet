import socket
import threading
import json
import logging
from datetime import datetime
from time import time

from .key_exchange import (
    get_parameters_bytes,
    load_parameters,
    generate_dh_keypair,
    load_peer_public_key,
    generate_shared_secret,
)
from .encryption import derive_key, decrypt_message, encrypt_message
from .auth import authenticate_user, register_user

HOST = "127.0.0.1"
PORT = 5555

clients = {}  # {socket: {"username": ..., "key": session_key}}
rate_limit = {}  # {username: [timestamps]}

# ---------- Logging ----------
logging.basicConfig(
    filename="logs/server.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr}")

    try:
        # ---------------- DH HANDSHAKE ----------------
        param_bytes = get_parameters_bytes()
        client_socket.send(param_bytes)

        client_public_bytes = client_socket.recv(4096)
        parameters = load_parameters(param_bytes)

        private_key, server_public_bytes = generate_dh_keypair(parameters)
        client_socket.send(server_public_bytes)

        client_public_key = load_peer_public_key(client_public_bytes)
        shared_secret = generate_shared_secret(private_key, client_public_key)

        session_key = derive_key(shared_secret)
        print("[SECURE SESSION ESTABLISHED]")

        # ---------------- AUTH ----------------
        authenticated = False
        username = None

        while not authenticated:
            encrypted_data = client_socket.recv(8192)
            decrypted = decrypt_message(session_key, encrypted_data)
            message = json.loads(decrypted)

            if message["type"] == "auth":
                action = message["action"]
                user = message["username"]
                pwd = message["password"]

                if action == "register":
                    success, msg = register_user(user, pwd)
                    response = {
                        "type": "auth_response",
                        "status": "success" if success else "fail",
                        "message": msg
                    }
                    if success:
                        authenticated = True
                        username = user

                elif action == "login":
                    if authenticate_user(user, pwd):
                        authenticated = True
                        username = user
                        response = {
                            "type": "auth_response",
                            "status": "success"
                        }
                    else:
                        response = {
                            "type": "auth_response",
                            "status": "fail",
                            "message": "Invalid credentials"
                        }

                encrypted_response = encrypt_message(
                    session_key, json.dumps(response)
                )
                client_socket.send(encrypted_response)

        # Add client
        clients[client_socket] = {
            "username": username,
            "key": session_key
        }

        logging.info(f"User authenticated: {username}")
        print(f"[AUTHENTICATED] {username}")

        broadcast_system_message(f"{username} joined the chat.")

        # ---------------- CHAT LOOP ----------------
        while True:
            encrypted_data = client_socket.recv(8192)
            if not encrypted_data:
                break

            decrypted = decrypt_message(session_key, encrypted_data)
            message = json.loads(decrypted)

            # ---- Rate Limiting ----
            now = time()
            if username not in rate_limit:
                rate_limit[username] = []

            rate_limit[username] = [
                t for t in rate_limit[username] if now - t < 5
            ]

            if len(rate_limit[username]) >= 5:
                continue

            rate_limit[username].append(now)

            # ---- Message Types ----
            if message["type"] == "chat":
                broadcast_message(username, message["content"])
                logging.info(f"Public message from {username}")

            elif message["type"] == "pm":
                send_private_message(
                    username,
                    message["to"],
                    message["content"]
                )
                logging.info(f"Private message {username} -> {message['to']}")

            elif message["type"] == "users":
                send_user_list(client_socket)

    except Exception as e:
        print("[ERROR]", e)

    finally:
        if client_socket in clients:
            left_user = clients[client_socket]["username"]
            broadcast_system_message(f"{left_user} left the chat.")
            logging.info(f"User disconnected: {left_user}")
            del clients[client_socket]

        print(f"[DISCONNECTED] {addr}")
        client_socket.close()


# ---------------- Broadcast Functions ----------------

def broadcast_message(sender_username, content):
    payload = json.dumps({
        "type": "chat",
        "from": sender_username,
        "content": content,
        "timestamp": datetime.now().strftime("%H:%M")
    })

    for client, data in list(clients.items()):
        try:
            encrypted = encrypt_message(data["key"], payload)
            client.send(encrypted)
        except:
            client.close()
            del clients[client]


def send_private_message(sender, target, content):
    payload = json.dumps({
        "type": "pm",
        "from": sender,
        "content": content,
        "timestamp": datetime.now().strftime("%H:%M")
    })

    found = False

    for client, data in list(clients.items()):
        if data["username"] == target:
            try:
                encrypted = encrypt_message(data["key"], payload)
                client.send(encrypted)
                found = True
            except:
                client.close()
                del clients[client]
            break

    if not found:
        # send error back
        for client, data in clients.items():
            if data["username"] == sender:
                error_payload = json.dumps({
                    "type": "error",
                    "message": f"User '{target}' not online."
                })
                encrypted = encrypt_message(data["key"], error_payload)
                client.send(encrypted)
                break


def send_user_list(requesting_socket):
    usernames = [data["username"] for data in clients.values()]

    payload = json.dumps({
        "type": "users",
        "list": usernames
    })

    data = clients.get(requesting_socket)
    if data:
        encrypted = encrypt_message(data["key"], payload)
        requesting_socket.send(encrypted)


def broadcast_system_message(text):
    payload = json.dumps({
        "type": "system",
        "message": text
    })

    for client, data in list(clients.items()):
        try:
            encrypted = encrypt_message(data["key"], payload)
            client.send(encrypted)
        except:
            client.close()
            del clients[client]


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[SERVER STARTED] {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, addr)
        )
        thread.start()