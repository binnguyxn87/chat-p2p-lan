import socket
import threading
from protocol import create_message, parse_message

class Peer:
    def __init__(self, my_name, listen_port):
        self.my_name = my_name
        self.listen_port = listen_port
        self.connections = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", listen_port))
        self.server_socket.listen(5)
        self.encrypt_hook = None   # hàm mã hóa - B sẽ gán vào sau
        self.decrypt_hook = None   # hàm giải mã - B sẽ gán vào sau

    def start_listening(self):
        print(f"[{self.my_name}] Đang lắng nghe tại cổng {self.listen_port}...")
        while True:
            try:
                conn, addr = self.server_socket.accept()
            except OSError:
                break
            print(f"[{self.my_name}] Kết nối mới từ {addr}")
            self.connections[addr] = conn
            t = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
            t.start()

    def _handle_connection(self, conn, addr):
        while True:
            try:
                data = conn.recv(1024)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                print(f"\n[{self.my_name}] Mất kết nối với {addr} (lỗi mạng).")
                self._remove_connection(addr)
                break

            if not data:
                print(f"\n[{self.my_name}] {addr} đã ngắt kết nối.")
                self._remove_connection(addr)
                break

            try:
                msg = parse_message(data.decode('utf-8'))
            except UnicodeDecodeError:
                print(f"[{self.my_name}] Nhận dữ liệu lỗi (không đọc được) từ {addr}, bỏ qua.")
                continue

            if msg:
                if msg['type'] == "MESSAGE" and self.decrypt_hook:
                    content = self.decrypt_hook(msg['payload'], addr)
                else:
                    content = msg['payload']
                print(f"\n[{msg['sender']}] ({msg['type']}): {content}")

    def _remove_connection(self, addr):
        if addr in self.connections:
            try:
                self.connections[addr].close()
            except:
                pass
            del self.connections[addr]

    def connect_to(self, ip, port):
        addr = (ip, port)
        if addr in self.connections:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((ip, port))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"[LỖI] Không kết nối được tới {addr}: {e}")
            return
        s.settimeout(None)
        self.connections[addr] = s
        t = threading.Thread(target=self._handle_connection, args=(s, addr), daemon=True)
        t.start()
        print(f"[{self.my_name}] Đã kết nối tới {addr}")

    def send_message(self, addr, text):
        if addr not in self.connections:
            print(f"[LỖI] Chưa kết nối tới {addr}")
            return False
        payload = self.encrypt_hook(text, addr) if self.encrypt_hook else text
        packet = create_message("MESSAGE", self.my_name, payload)
        try:
            self.connections[addr].send(packet.encode('utf-8'))
            return True
        except (ConnectionResetError, ConnectionAbortedError, OSError, BrokenPipeError):
            print(f"[LỖI] Không gửi được tới {addr}, có thể đã ngắt kết nối.")
            self._remove_connection(addr)
            return False

    def broadcast(self, text):
        dead_peers = []
        for addr, conn in list(self.connections.items()):
            payload = self.encrypt_hook(text, addr) if self.encrypt_hook else text
            packet = create_message("MESSAGE", self.my_name, payload)
            try:
                conn.send(packet.encode('utf-8'))
            except (ConnectionResetError, ConnectionAbortedError, OSError, BrokenPipeError):
                dead_peers.append(addr)
        for addr in dead_peers:
            self._remove_connection(addr)

    def list_peers(self):
        return list(self.connections.keys())
    def shutdown(self):
        """Đóng tất cả kết nối và socket lắng nghe một cách lịch sự trước khi thoát"""
        for addr, conn in list(self.connections.items()):
            try:
                conn.close()
            except:
                pass
        self.connections.clear()
        try:
            self.server_socket.close()
        except:
            pass
        print(f"[{self.my_name}] Đã đóng toàn bộ kết nối và thoát.")