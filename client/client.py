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

HOST = "127.0.0.1"
PORT = 5555

session_key = None


def receive_messages(sock):
    global session_key
    while True:
        try:
            encrypted_data = sock.recv(8192)
            if not encrypted_data:
                break

            decrypted = decrypt_message(session_key, encrypted_data)
            message = json.loads(decrypted)

            if message["type"] == "chat":
                print(f"\n[Public] {message['from']}: {message['content']}")
                print("You: ", end="")

            elif message["type"] == "pm":
                print(f"\n[Private] {message['from']}: {message['content']}")
                print("You: ", end="")

            elif message["type"] == "users":
                print("\n[Online Users]")
                for user in message["list"]:
                    print(" -", user)
                print("You: ", end="")

            elif message["type"] == "error":
                print(f"\n[ERROR] {message['message']}")
                print("You: ", end="")

        except:
            break


def start_client():
    global session_key

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print("[CONNECTED]")

    # ---------------- DH HANDSHAKE ----------------
    param_bytes = client.recv(4096)
    parameters = load_parameters(param_bytes)

    private_key, public_bytes = generate_dh_keypair(parameters)
    client.send(public_bytes)

    server_public_bytes = client.recv(4096)
    server_public_key = load_peer_public_key(server_public_bytes)

    shared_secret = generate_shared_secret(private_key, server_public_key)
    session_key = derive_key(shared_secret)

    print("[SECURE SESSION ESTABLISHED]")

    # ---------------- AUTH ----------------
    while True:
        print("\n1) Login")
        print("2) Register")
        choice = input("Select: ")

        username = input("Username: ")
        password = input("Password: ")

        action = "login" if choice == "1" else "register"

        auth_message = {
            "type": "auth",
            "action": action,
            "username": username,
            "password": password
        }

        encrypted = encrypt_message(session_key, json.dumps(auth_message))
        client.send(encrypted)

        response_data = client.recv(8192)
        decrypted = decrypt_message(session_key, response_data)
        response = json.loads(decrypted)

        if response["status"] == "success":
            print("[AUTH SUCCESS]")
            break
        else:
            print("[AUTH FAILED]", response.get("message", ""))

    # Start receive thread AFTER auth
    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.daemon = True
    thread.start()

    # ---------------- CHAT ----------------
    while True:
        message = input("You: ")

        if message.startswith("/pm"):
            parts = message.split(" ", 2)
            if len(parts) < 3:
                print("Usage: /pm username message")
                continue

            chat_message = {
                "type": "pm",
                "to": parts[1],
                "content": parts[2]
            }

        elif message == "/users":
            chat_message = {
                "type": "users"
            }

        else:
            chat_message = {
                "type": "chat",
                "content": message
            }

        encrypted = encrypt_message(session_key, json.dumps(chat_message))
        client.send(encrypted)