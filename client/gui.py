import sys
from PyQt5.QtWidgets import QApplication
from .gui_login import LoginWindow


def start_gui():
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())