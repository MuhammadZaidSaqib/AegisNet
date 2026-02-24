from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QListWidget,
    QLabel, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class MessageBubble(QFrame):
    def __init__(self, text, is_self=False):
        super().__init__()

        layout = QVBoxLayout()
        label = QLabel(text)
        label.setWordWrap(True)

        label.setFont(QFont("Consolas", 10))
        layout.addWidget(label)
        self.setLayout(layout)

        if is_self:
            self.setStyleSheet("""
                background-color: #001F1F;
                border: 1px solid #00FF9C;
                border-radius: 6px;
                padding: 6px;
            """)
        else:
            self.setStyleSheet("""
                background-color: #111111;
                border: 1px solid #00FF00;
                border-radius: 6px;
                padding: 6px;
            """)


class ChatWindow(QWidget):
    def __init__(self, client):
        super().__init__()
        self.client = client

        self.setWindowTitle("AegisNet // Secure Channel")
        self.setGeometry(200, 80, 1000, 650)

        main_layout = QHBoxLayout(self)

        # ===== LEFT SIDE =====
        left_layout = QVBoxLayout()

        header = QLabel("🟢 SECURE CHANNEL ACTIVE // AES-GCM // DH KEY EXCHANGE")
        header.setStyleSheet("color: #00FF00; font-weight: bold;")
        left_layout.addWidget(header)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)

        self.chat_container = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setAlignment(Qt.AlignTop)

        self.scroll_area.setWidget(self.chat_container)
        left_layout.addWidget(self.scroll_area)

        # Input Bar
        bottom_layout = QHBoxLayout()

        self.input = QLineEdit()
        self.input.setPlaceholderText(">> transmit encrypted payload...")
        self.input.setStyleSheet("""
            background-color: black;
            color: #00FF00;
            border: 1px solid #00FF00;
            padding: 6px;
        """)
        bottom_layout.addWidget(self.input)

        send_btn = QPushButton("SEND")
        send_btn.setStyleSheet("""
            background-color: black;
            color: #00FF00;
            border: 1px solid #00FF00;
            padding: 6px;
        """)
        send_btn.clicked.connect(self.send_message)
        bottom_layout.addWidget(send_btn)

        left_layout.addLayout(bottom_layout)

        # ===== RIGHT SIDE =====
        right_layout = QVBoxLayout()

        users_label = QLabel("ONLINE NODES")
        users_label.setStyleSheet("color: #00FF00;")
        right_layout.addWidget(users_label)

        self.users_list = QListWidget()
        self.users_list.setStyleSheet("""
            background-color: black;
            color: #00FF00;
            border: 1px solid #00FF00;
        """)
        right_layout.addWidget(self.users_list)

        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(right_layout, 1)

        self.client.on_message = self.display_message
        self.apply_cyberpunk_theme()

    # =========================
    def send_message(self):
        text = self.input.text()
        if not text:
            return

        if text.startswith("/pm"):
            parts = text.split(" ", 2)
            if len(parts) < 3:
                return
            payload = {
                "type": "pm",
                "to": parts[1],
                "content": parts[2]
            }
        elif text == "/users":
            payload = {"type": "users"}
        else:
            payload = {
                "type": "chat",
                "content": text
            }

        self.client.send_message(payload)
        self.add_message(f"[YOU] {text}", is_self=True)
        self.input.clear()

    # =========================
    def display_message(self, message):
        if message["type"] == "chat":
            text = f"[{message['timestamp']}] {message['from']}: {message['content']}"
            self.add_message(text)

        elif message["type"] == "pm":
            text = f"[PRIVATE {message['timestamp']}] {message['from']}: {message['content']}"
            self.add_message(text)

        elif message["type"] == "system":
            text = f"[SYSTEM ALERT] {message['message']}"
            self.add_message(text)

        elif message["type"] == "users":
            self.users_list.clear()
            self.users_list.addItems(message["list"])

        elif message["type"] == "error":
            self.add_message(f"[ERROR] {message['message']}")

    # =========================
    def add_message(self, text, is_self=False):
        bubble = MessageBubble(text, is_self)
        container = QHBoxLayout()

        if is_self:
            container.addStretch()
            container.addWidget(bubble)
        else:
            container.addWidget(bubble)
            container.addStretch()

        wrapper = QWidget()
        wrapper.setLayout(container)
        self.chat_layout.addWidget(wrapper)

        self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        )

    # =========================
    def apply_cyberpunk_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: black;
                color: #00FF00;
                font-family: Consolas;
            }
        """)