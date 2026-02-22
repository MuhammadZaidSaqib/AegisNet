from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton,
    QListWidget, QLabel, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt
import base64
import json
import os
from .encryption import decrypt_message


class ChatWindow(QWidget):
    def __init__(self, secure_client):
        super().__init__()
        self.client = secure_client

        self.setWindowTitle("AegisNet Secure Messenger")
        self.setGeometry(200, 200, 900, 550)

        self.init_ui()
        self.apply_dark_theme()

        # Connect network callbacks
        self.client.on_message = self.display_message
        self.client.on_user_list = self.update_users

        self.load_history()

    # -----------------------------------
    # UI Layout
    # -----------------------------------
    def init_ui(self):
        main_layout = QHBoxLayout()

        # LEFT SIDE (Chat)
        left_layout = QVBoxLayout()

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        left_layout.addWidget(self.chat_area)

        bottom_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type message or /pm user message")
        self.message_input.returnPressed.connect(self.send_message)
        bottom_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        bottom_layout.addWidget(self.send_button)

        self.file_button = QPushButton("Send File")
        self.file_button.clicked.connect(self.send_file)
        bottom_layout.addWidget(self.file_button)

        left_layout.addLayout(bottom_layout)

        # RIGHT SIDE (Online Users)
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Online Users"))

        self.user_list = QListWidget()
        self.user_list.setMaximumWidth(200)
        right_layout.addWidget(self.user_list)

        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(right_layout, 1)

        self.setLayout(main_layout)

    # -----------------------------------
    # Dark Theme
    # -----------------------------------
    def apply_dark_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #E0E0E0;
                font-family: Segoe UI;
                font-size: 12px;
            }
            QTextEdit {
                background-color: #1E1E1E;
                border: 1px solid #2A2A2A;
            }
            QLineEdit {
                background-color: #1E1E1E;
                border: 1px solid #2A2A2A;
                padding: 5px;
            }
            QPushButton {
                background-color: #2A2A2A;
                border: 1px solid #3A3A3A;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #3A3A3A;
            }
            QListWidget {
                background-color: #1E1E1E;
                border: 1px solid #2A2A2A;
            }
        """)

    # -----------------------------------
    # Send Text Message
    # -----------------------------------
    def send_message(self):
        message = self.message_input.text().strip()
        if not message:
            return

        self.chat_area.append(f"You: {message}")
        self.client.send_message(message)
        self.message_input.clear()

        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )

    # -----------------------------------
    # Send File
    # -----------------------------------
    def send_file(self):
        selected_user = self.user_list.currentItem()

        if not selected_user:
            QMessageBox.warning(
                self,
                "No User Selected",
                "Select a user to send a file."
            )
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")

        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                encoded_data = base64.b64encode(f.read()).decode()

            payload = json.dumps({
                "type": "file",
                "to": selected_user.text(),
                "filename": os.path.basename(file_path),
                "data": encoded_data
            })

            self.client.send_message(payload)

            self.chat_area.append(
                f"You sent file '{os.path.basename(file_path)}' to {selected_user.text()}"
            )

        except Exception as e:
            QMessageBox.critical(self, "File Error", str(e))

    # -----------------------------------
    # Display Incoming Message
    # -----------------------------------
    def display_message(self, message):
        self.chat_area.append(message)
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )

    # -----------------------------------
    # Update Online Users
    # -----------------------------------
    def update_users(self, users):
        self.user_list.clear()
        self.user_list.addItems(users)

    # -----------------------------------
    # Load Encrypted History
    # -----------------------------------
    def load_history(self):
        try:
            if not self.client.username:
                return

            filename = f"history/{self.client.username}.bin"

            if not os.path.exists(filename):
                return

            with open(filename, "rb") as f:
                lines = f.readlines()

            for line in lines:
                try:
                    decrypted = decrypt_message(
                        self.client.session_key,
                        line.strip()
                    )
                    self.chat_area.append(decrypted)
                except:
                    continue

        except:
            pass