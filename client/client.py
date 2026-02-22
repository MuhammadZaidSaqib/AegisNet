import socket
import threading

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
                break

            decrypted = decrypt_message(session_key, data)
            print(f"\n[RECEIVED] {decrypted}")
        except Exception as e:
            print(f"[RECEIVE ERROR] {e}")
            break


def start_client():
    global session_key

    # ✅ CREATE SOCKET FIRST
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print("[CONNECTED TO SERVER]")

    # --- Receive DH parameters from server ---
    param_bytes = client.recv(4096)
    parameters = load_parameters(param_bytes)

    # Generate client keypair
    private_key, public_bytes = generate_dh_keypair(parameters)

    # Send client public key
    client.send(public_bytes)

    # Receive server public key
    server_public_bytes = client.recv(4096)

    server_public_key = load_peer_public_key(server_public_bytes)

    shared_secret = generate_shared_secret(private_key, server_public_key)

    session_key = derive_key(shared_secret)

    print("[SECURE SESSION ESTABLISHED]")

    # Start receiving thread
    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.daemon = True
    thread.start()

    while True:
        message = input("You: ")
        encrypted = encrypt_message(session_key, message)
        client.send(encrypted)