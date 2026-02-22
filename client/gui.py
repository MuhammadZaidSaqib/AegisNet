import sys
import threading
import json
import socket

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QMessageBox,
    QListWidget
)

from .client import (
    HOST, PORT,
    derive_key, encrypt_message, decrypt_message,
    load_parameters, generate_dh_keypair,
    load_peer_public_key, generate_shared_secret
)


class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AegisNet Secure Messenger")
        self.setGeometry(200, 200, 800, 500)

        self.session_key = None
        self.client_socket = None
        self.username = None

        self.init_ui()
        self.connect_to_server()

    def init_ui(self):
        main_layout = QHBoxLayout()

        # Left side: Chat
        left_layout = QVBoxLayout()

        self.status_label = QLabel("Connecting...")
        left_layout.addWidget(self.status_label)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        left_layout.addWidget(self.chat_area)

        bottom_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        bottom_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        bottom_layout.addWidget(self.send_button)

        left_layout.addLayout(bottom_layout)

        # Right side: Online users
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Online Users"))
        self.user_list_widget = QListWidget()
        right_layout.addWidget(self.user_list_widget)

        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(right_layout, 1)

        self.setLayout(main_layout)

    # -----------------------------
    # Connect + Handshake
    # -----------------------------
    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))

            param_bytes = self.client_socket.recv(4096)
            parameters = load_parameters(param_bytes)

            private_key, public_bytes = generate_dh_keypair(parameters)
            self.client_socket.send(public_bytes)

            server_public_bytes = self.client_socket.recv(4096)
            server_public_key = load_peer_public_key(server_public_bytes)

            shared_secret = generate_shared_secret(private_key, server_public_key)
            self.session_key = derive_key(shared_secret)

            self.status_label.setText("🔐 Secure Connection Established")

            self.show_auth_screen()

            thread = threading.Thread(target=self.receive_messages)
            thread.daemon = True
            thread.start()

        except Exception as e:
            QMessageBox.critical(self, "Connection Error", str(e))

    # -----------------------------
    # Login / Register UI
    # -----------------------------
    def show_auth_screen(self):
        while True:
            username, ok = QInputDialog.getText(self, "Login/Register", "Username:")
            if not ok:
                sys.exit()

            password, ok = QInputDialog.getText(self, "Login/Register", "Password:")
            if not ok:
                sys.exit()

            action_choice, ok = QInputDialog.getItem(
                self,
                "Select Action",
                "Choose:",
                ["Login", "Register"],
                0,
                False
            )

            action = "login" if action_choice == "Login" else "register"

            request = {
                "action": action,
                "username": username,
                "password": password
            }

            encrypted = encrypt_message(self.session_key, json.dumps(request))
            self.client_socket.send(encrypted)

            response_data = self.client_socket.recv(8192)
            decrypted = decrypt_message(self.session_key, response_data)
            response = json.loads(decrypted)

            if response["status"] == "success":
                self.username = username
                break
            else:
                QMessageBox.warning(self, "Error", response.get("message", "Failed"))

    # -----------------------------
    # Send Message
    # -----------------------------
    def send_message(self):
        message = self.message_input.text()
        if message:
            encrypted = encrypt_message(self.session_key, message)
            self.client_socket.send(encrypted)
            self.message_input.clear()

    # -----------------------------
    # Receive Messages
    # -----------------------------
    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    break

                decrypted = decrypt_message(self.session_key, data)

                try:
                    parsed = json.loads(decrypted)
                    if parsed.get("type") == "user_list":
                        self.update_user_list(parsed["users"])
                        continue
                except:
                    pass

                self.chat_area.append(decrypted)

            except:
                break

    def update_user_list(self, users):
        self.user_list_widget.clear()
        for user in users:
            self.user_list_widget.addItem(user)


def start_gui():
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec_())