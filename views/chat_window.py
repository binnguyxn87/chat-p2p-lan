from PyQt5.QtWidgets import (
    QWidget,
    QListWidget,
    QTextBrowser,
    QLineEdit,
    QPushButton,
    QLabel,
    QVBoxLayout,
    QHBoxLayout
)


class ChatWindow(QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("P2P Chat LAN")
        self.resize(900, 600)

        self.setup_ui()

    def setup_ui(self):

        # Danh sách peer
        peer_label = QLabel("Online Peers")
        self.peer_list = QListWidget()

        left_layout = QVBoxLayout()
        left_layout.addWidget(peer_label)
        left_layout.addWidget(self.peer_list)

        # Khu vực chat
        chat_label = QLabel("Chat")
        self.chat_area = QTextBrowser()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Nhập tin nhắn...")

        self.send_button = QPushButton("Send")

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.message_input)
        bottom_layout.addWidget(self.send_button)

        right_layout = QVBoxLayout()
        right_layout.addWidget(chat_label)
        right_layout.addWidget(self.chat_area)
        right_layout.addLayout(bottom_layout)

        # Layout chính
        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 3)

        self.setLayout(main_layout)