class AppController:

    def __init__(self):

        self.login_window = LoginWindow()
        self.chat_window = ChatWindow()

        self.login_window.controller = self