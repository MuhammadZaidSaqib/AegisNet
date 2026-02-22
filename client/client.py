import socket
import threading
import json
import sys

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
            data = sock.recv(8192)
            if not data:
                print("\n[SERVER DISCONNECTED]")
                break

            decrypted = decrypt_message(session_key, data)
            print(f"\n{decrypted}\nYou: ", end="")

        except Exception as e:
            print(f"\n[RECEIVE ERROR] {e}")
            break

    sock.close()
    sys.exit()


def start_client():
    global session_key

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
    except Exception as e:
        print(f"[CONNECTION FAILED] {e}")
        return

    print("[CONNECTED TO SERVER]")

    param_bytes = client.recv(4096)
    parameters = load_parameters(param_bytes)

    private_key, public_bytes = generate_dh_keypair(parameters)

    client.send(public_bytes)

    server_public_bytes = client.recv(4096)
    server_public_key = load_peer_public_key(server_public_bytes)

    shared_secret = generate_shared_secret(private_key, server_public_key)

    session_key = derive_key(shared_secret)

    print("[SECURE SESSION ESTABLISHED]")


    while True:
        print("\n1) Login")
        print("2) Register")
        choice = input("Select: ").strip()

        if choice not in ["1", "2"]:
            print("Invalid choice.")
            continue

        username = input("Username: ").strip()
        password = input("Password: ").strip()

        request = {
            "action": "login" if choice == "1" else "register",
            "username": username,
            "password": password
        }

        encrypted_request = encrypt_message(
            session_key, json.dumps(request)
        )
        client.send(encrypted_request)

        response_data = client.recv(8192)
        decrypted_response = decrypt_message(session_key, response_data)

        response = json.loads(decrypted_response)

        if response["status"] == "success":
            print("[AUTH SUCCESSFUL]")
            break
        else:
            print("[AUTH FAILED]", response.get("message", ""))


    thread = threading.Thread(
        target=receive_messages,
        args=(client,)
    )
    thread.daemon = True
    thread.start()


    while True:
        try:
            message = input("You: ")

            if message.lower() == "/exit":
                print("Disconnecting...")
                client.close()
                break

            encrypted = encrypt_message(session_key, message)
            client.send(encrypted)

        except Exception as e:
            print(f"[SEND ERROR] {e}")
            break