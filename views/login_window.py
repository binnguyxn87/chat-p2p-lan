from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QMessageBox
)


class LoginWindow(QWidget):

    def __init__(self):
        super().__init__()

        self.controller = None

        self.setWindowTitle("P2P Chat LAN")
        self.setFixedSize(400, 250)

        self.setup_ui()

    def setup_ui(self):

        # Tiêu đề
        title = QLabel("P2P CHAT LAN")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            font-size:20px;
            font-weight:bold;
        """)

        # Username
        username_label = QLabel("Username")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Nhập tên của bạn")

        # Port
        port_label = QLabel("Port")

        self.port_input = QLineEdit()
        self.port_input.setValidator(QIntValidator(1, 65535))
        self.port_input.setText("5000")

        # Button
        self.start_button = QPushButton("Start")
        self.start_button.setFixedHeight(40)

        self.start_button.clicked.connect(self.start_clicked)

        layout = QVBoxLayout()

        layout.setSpacing(12)
        layout.setContentsMargins(30, 30, 30, 30)

        layout.addWidget(title)
        layout.addWidget(username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.start_button)

        self.setLayout(layout)

    def start_clicked(self):
        print("Đã nhấn Start")

        username = self.username_input.text().strip()
        port = self.port_input.text().strip()

        print(username, port)

        if username == "":
            QMessageBox.warning(
                self,
                "Lỗi",
                "Username không được để trống"
            )
            return

        if self.controller:
            print("Gọi AppController.login()")
            self.controller.login(username, port)