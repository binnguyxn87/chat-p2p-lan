import socket
import threading
from protocol import create_message, parse_message

HOST = "192.168.1.125"
PORT = 5000
MY_NAME = "Client"

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print(f"[CLIENT] Đã kết nối tới {HOST}:{PORT}")

def receive_loop():
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                print("[CLIENT] Đối phương đã ngắt kết nối.")
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
    client_socket.send(packet.encode('utf-8'))

client_socket.close()