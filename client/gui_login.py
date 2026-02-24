from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit,
    QPushButton, QLabel, QMessageBox
)
from .network import SecureClient
from .gui_chat import ChatWindow


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.client = SecureClient()
        self.client.connect()

        self.setWindowTitle("AegisNet Secure Login")
        self.setGeometry(500, 200, 300, 200)

        layout = QVBoxLayout()

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        layout.addWidget(self.username)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.login)
        layout.addWidget(login_btn)

        register_btn = QPushButton("Register")
        register_btn.clicked.connect(self.register)
        layout.addWidget(register_btn)

        self.setLayout(layout)

    def login(self):
        self.authenticate("login")

    def register(self):
        self.authenticate("register")

    def authenticate(self, action):
        success, msg = self.client.authenticate(
            action,
            self.username.text(),
            self.password.text()
        )

        if success:
            self.chat = ChatWindow(self.client)
            self.chat.show()
            self.close()
        else:
            QMessageBox.warning(self, "Error", msg)