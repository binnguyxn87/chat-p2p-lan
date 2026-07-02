import sys
import threading
from peer import Peer

if len(sys.argv) < 3:
    print("Cách dùng: python run_peer.py <ten> <cong_lang_nghe>")
    sys.exit(1)

name = sys.argv[1]
port = int(sys.argv[2])

peer = Peer(name, port)

# Chạy việc lắng nghe kết nối trong thread riêng (vì nó là vòng lặp vô hạn)
listen_thread = threading.Thread(target=peer.start_listening, daemon=True)
listen_thread.start()

print("Lệnh dùng được:")
print("  connect <ip> <port>        - ket noi toi 1 peer")
print("  send <ip> <port> <noi dung>  - gui tin nhan rieng")
print("  broadcast <noi dung>        - gui cho tat ca peer dang ket noi")
print("  list                        - xem danh sach peer dang ket noi")
print("  exit                        - thoat")

while True:
    cmd = input(">> ").strip()
    if cmd == "":
        continue
    parts = cmd.split(" ", 3)

    if parts[0] == "exit":
        break

    elif parts[0] == "connect" and len(parts) == 3:
        ip, target_port = parts[1], int(parts[2])
        peer.connect_to(ip, target_port)

    elif parts[0] == "send" and len(parts) == 4:
        ip, target_port, text = parts[1], int(parts[2]), parts[3]
        peer.send_message((ip, target_port), text)

    elif parts[0] == "broadcast" and len(parts) >= 2:
        text = cmd[len("broadcast "):]
        peer.broadcast(text)

    elif parts[0] == "list":
        print(peer.list_peers())

    else:
        print("Lệnh không hợp lệ hoặc thiếu tham số.")