from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox
)


class LoginWindow(QWidget):
    def __init__(self, secure_client, on_success):
        super().__init__()
        self.client = secure_client
        self.on_success = on_success

        self.setWindowTitle("AegisNet Login")
        self.setGeometry(300, 300, 300, 200)

        layout = QVBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def login(self):
        self.authenticate("login")

    def register(self):
        self.authenticate("register")

    def authenticate(self, action):
        username = self.username_input.text()
        password = self.password_input.text()

        success, message = self.client.authenticate(
            action, username, password
        )

        if success:
            self.on_success()
            self.close()
        else:
            QMessageBox.warning(self, "Error", message)