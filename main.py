"""
Điểm khởi chạy chính của ứng dụng Chat P2P LAN.
Chạy: python main.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ui"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "network"))

from gui import LoginWindow

if __name__ == "__main__":
    app = LoginWindow()
    app.mainloop()
