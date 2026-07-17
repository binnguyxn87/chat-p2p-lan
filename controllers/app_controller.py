from views.login_window import LoginWindow
from views.chat_window import ChatWindow


class AppController:

    def __init__(self):
        self.login_window = LoginWindow()
        self.chat_window = ChatWindow()

        self.login_window.controller = self

    def start(self):
        self.login_window.show()

    def login(self, username, port):
        print("Đã vào AppController")
        print("Username:", username)
        print("Port:", port)

        self.login_window.close()

        print("Đã đóng Login")

        self.chat_window.show()

        print("Đã mở Chat")