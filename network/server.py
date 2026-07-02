import socket
import threading
from protocol import create_message, parse_message

HOST = "0.0.0.0"
PORT = 5000
MY_NAME = "Server"   # sau này đổi thành username thật

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"[SERVER] Đang lắng nghe tại {HOST}:{PORT}...")

conn, addr = server_socket.accept()
print(f"[SERVER] Đã kết nối với {addr}")

def receive_loop():
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                print("[SERVER] Đối phương đã ngắt kết nối.")
                break
            msg = parse_message(data.decode('utf-8'))
            if msg:
                print(f"\n[{msg['sender']}] ({msg['type']}): {msg['payload']}")
        except:
            break

thread = threading.Thread(target=receive_loop, daemon=True)
thread.start()

while True:
    text = input()
    if text.lower() == "exit":
        break
    packet = create_message("MESSAGE", MY_NAME, text)
    conn.send(packet.encode('utf-8'))

conn.close()
server_socket.close()