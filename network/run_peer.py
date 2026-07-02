import sys
import threading
from peer import Peer
from discovery import Discovery

if len(sys.argv) < 3:
    print("Cách dùng: python run_peer.py <ten> <cong_lang_nghe>")
    sys.exit(1)

name = sys.argv[1]
port = int(sys.argv[2])

peer = Peer(name, port)

# Hàm này sẽ được Discovery gọi ngược lại mỗi khi tìm thấy 1 peer mới
def handle_peer_found(peer_name, ip, tcp_port):
    addr = (ip, tcp_port)
    if addr in peer.connections:
        return   # đã kết nối rồi, không kết nối lại
    try:
        peer.connect_to(ip, tcp_port)
        print(f"\n[TỰ ĐỘNG] Đã phát hiện và kết nối tới {peer_name} tại {addr}")
    except Exception as e:
        pass   # có thể do 2 peer cùng lúc thử connect nhau, bỏ qua lỗi trùng

listen_thread = threading.Thread(target=peer.start_listening, daemon=True)
listen_thread.start()

discovery = Discovery(name, port, handle_peer_found)
discovery.start()

print("Lệnh dùng được:")
print("  connect <ip> <port>          - ket noi thu cong toi 1 peer")
print("  send <ip> <port> <noi dung>  - gui tin nhan rieng")
print("  broadcast <noi dung>         - gui cho tat ca peer dang ket noi")
print("  list                         - xem danh sach peer dang ket noi")
print("  exit                         - thoat")

while True:
    cmd = input(">> ").strip()
    if cmd == "":
        continue
    parts = cmd.split(" ", 3)

    if parts[0] == "exit":
        peer.shutdown()
        break
    elif parts[0] == "connect" and len(parts) == 3:
        peer.connect_to(parts[1], int(parts[2]))
    elif parts[0] == "send" and len(parts) == 4:
        peer.send_message((parts[1], int(parts[2])), parts[3])
    elif parts[0] == "broadcast" and len(parts) >= 2:
        peer.broadcast(cmd[len("broadcast "):])
    elif parts[0] == "list":
        print(peer.list_peers())
    else:
        print("Lệnh không hợp lệ hoặc thiếu tham số.")