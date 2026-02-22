import socket
import threading

from .key_exchange import (
    get_parameters_bytes,
    load_parameters,
    generate_dh_keypair,
    load_peer_public_key,
    generate_shared_secret,
)

from .encryption import derive_key, decrypt_message, encrypt_message


HOST = "0.0.0.0"
PORT = 5555

clients = {}
# { socket: session_key }


def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr}")

    try:
        # --- STEP 1: Send DH parameters ---
        param_bytes = get_parameters_bytes()
        client_socket.send(param_bytes)

        # --- STEP 2: Receive client public key ---
        client_public_bytes = client_socket.recv(4096)

        parameters = load_parameters(param_bytes)

        # --- STEP 3: Generate server keypair ---
        private_key, server_public_bytes = generate_dh_keypair(parameters)

        # --- STEP 4: Send server public key ---
        client_socket.send(server_public_bytes)

        # --- STEP 5: Compute shared secret ---
        client_public_key = load_peer_public_key(client_public_bytes)
        shared_secret = generate_shared_secret(private_key, client_public_key)

        session_key = derive_key(shared_secret)

        clients[client_socket] = session_key

        print(f"[SECURE SESSION ESTABLISHED] {addr}")

        # --- Secure Messaging Loop ---
        while True:
            encrypted_data = client_socket.recv(8192)
            if not encrypted_data:
                break

            decrypted_message = decrypt_message(session_key, encrypted_data)

            print(f"[{addr}] {decrypted_message}")

            broadcast(decrypted_message, client_socket)

    except Exception as e:
        print(f"[ERROR] {addr} -> {e}")

    finally:
        print(f"[DISCONNECTED] {addr}")
        clients.pop(client_socket, None)
        client_socket.close()


def broadcast(message, sender_socket):
    for client, key in clients.items():
        if client != sender_socket:
            try:
                encrypted = encrypt_message(key, message)
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
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()