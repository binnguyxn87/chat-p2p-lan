import socket
import threading
from protocol import create_message, parse_message

class Peer:
    def __init__(self, my_name, listen_port):
        self.my_name = my_name
        self.listen_port = listen_port
        self.connections = {}   # lưu các kết nối đang mở: {địa_chỉ: socket_object}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", listen_port))
        self.server_socket.listen(5)   # cho phép tối đa 5 kết nối chờ trong hàng đợi

    def start_listening(self):
        """Chạy nền, liên tục chấp nhận kết nối mới từ các peer khác"""
        print(f"[{self.my_name}] Đang lắng nghe tại cổng {self.listen_port}...")
        while True:
            conn, addr = self.server_socket.accept()
            print(f"[{self.my_name}] Kết nối mới từ {addr}")
            self.connections[addr] = conn
            # Mỗi kết nối mới -> 1 thread riêng để nhận tin nhắn, không chặn các kết nối khác
            t = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
            t.start()

    def _handle_connection(self, conn, addr):
        """Xử lý nhận tin nhắn liên tục từ 1 peer cụ thể"""
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print(f"[{self.my_name}] {addr} đã ngắt kết nối.")
                    del self.connections[addr]
                    break
                msg = parse_message(data.decode('utf-8'))
                if msg:
                    print(f"\n[{msg['sender']}] ({msg['type']}): {msg['payload']}")
            except:
                break

    def connect_to(self, ip, port):
        """Chủ động kết nối tới 1 peer khác"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        addr = (ip, port)
        self.connections[addr] = s
        t = threading.Thread(target=self._handle_connection, args=(s, addr), daemon=True)
        t.start()
        print(f"[{self.my_name}] Đã kết nối tới {addr}")

    def send_message(self, addr, text):
        """Gửi tin nhắn tới 1 peer cụ thể (addr là tuple (ip, port))"""
        if addr not in self.connections:
            print(f"[LỖI] Chưa kết nối tới {addr}")
            return
        packet = create_message("MESSAGE", self.my_name, text)
        self.connections[addr].send(packet.encode('utf-8'))

    def broadcast(self, text):
        """Gửi tin nhắn tới TẤT CẢ peer đang kết nối"""
        packet = create_message("MESSAGE", self.my_name, text)
        for addr, conn in list(self.connections.items()):
            try:
                conn.send(packet.encode('utf-8'))
            except:
                pass

    def list_peers(self):
        return list(self.connections.keys())