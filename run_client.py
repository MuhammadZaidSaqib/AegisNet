import sys
from PyQt5.QtWidgets import QApplication
from client.network import SecureClient
from client.gui_login import LoginWindow
from client.gui_chat import ChatWindow

HOST = "127.0.0.1"
PORT = 5555


def main():
    app = QApplication(sys.argv)

    client = SecureClient(HOST, PORT)
    client.connect()

    def open_chat():
        chat = ChatWindow(client)
        chat.show()

    login = LoginWindow(client, open_chat)
    login.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()