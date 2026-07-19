import socket
import threading
from protocol import create_message, parse_message


class Peer:
    def __init__(self, my_name, listen_port):
        self.my_name = my_name
        self.listen_port = listen_port
        self.connections = {}

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", listen_port))
        self.server_socket.listen(5)

        # Hooks / callback - UI và Bảo mật gắn vào đây
        self.encrypt_hook = None
        self.decrypt_hook = None
        self.on_message_received = None      # (sender_name, content, addr)
        self.on_peer_connected = None         # (addr, is_initiator)
        self.on_peer_disconnected = None      # (addr)
        self.crypto_bridge_handler = None     # (msg_type, sender, payload, addr) - gán bởi CryptoBridge

    # ---------- LẮNG NGHE & KẾT NỐI ----------

    def start_listening(self):
        while True:
            try:
                conn, addr = self.server_socket.accept()
            except OSError:
                break
            self.connections[addr] = conn
            if self.on_peer_connected:
                self.on_peer_connected(addr, False)
            t = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
            t.start()

    def connect_to(self, ip, port):
        addr = (ip, port)
        if addr in self.connections:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((ip, port))
        except (socket.timeout, ConnectionRefusedError, OSError):
            return
        s.settimeout(None)
        self.connections[addr] = s
        if self.on_peer_connected:
            self.on_peer_connected(addr, True)
        t = threading.Thread(target=self._handle_connection, args=(s, addr), daemon=True)
        t.start()

    # ---------- NHẬN DỮ LIỆU ----------
    # Dùng khung tin nhắn theo dòng (mỗi message kết thúc bằng '\n') để tránh
    # lỗi phân mảnh/gộp gói tin của TCP khi nhiều tin nhắn gửi liên tiếp nhanh.

    def _handle_connection(self, conn, addr):
        buffer = ""
        while True:
            try:
                data = conn.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                self._remove_connection(addr)
                break

            if not data:
                self._remove_connection(addr)
                break

            try:
                buffer += data.decode('utf-8')
            except UnicodeDecodeError:
                continue

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue
                self._process_line(line, addr)

    def _process_line(self, line, addr):
        msg = parse_message(line)
        if not msg:
            return

        if msg['type'] in ("PUBKEY", "KEY_EXCHANGE"):
            if self.crypto_bridge_handler:
                self.crypto_bridge_handler(msg['type'], msg['sender'], msg['payload'], addr)
            return

        if msg['type'] == "MESSAGE" and self.decrypt_hook:
            content = self.decrypt_hook(msg['payload'], addr)
        else:
            content = msg['payload']

        if self.on_message_received:
            self.on_message_received(msg['sender'], content, addr)

    def _remove_connection(self, addr):
        if addr in self.connections:
            try:
                self.connections[addr].close()
            except Exception:
                pass
            del self.connections[addr]
            if self.on_peer_disconnected:
                self.on_peer_disconnected(addr)

    # ---------- GỬI DỮ LIỆU ----------

    def _send_raw(self, addr, packet_str):
        if addr not in self.connections:
            return False
        try:
            self.connections[addr].send((packet_str + "\n").encode('utf-8'))
            return True
        except (ConnectionResetError, ConnectionAbortedError, OSError, BrokenPipeError):
            self._remove_connection(addr)
            return False

    def send_message(self, addr, text):
        payload = self.encrypt_hook(text, addr) if self.encrypt_hook else text
        packet = create_message("MESSAGE", self.my_name, payload)
        return self._send_raw(addr, packet)

    def broadcast(self, text):
        for addr in list(self.connections.keys()):
            self.send_message(addr, text)

    def send_control(self, addr, msg_type, payload):
        packet = create_message(msg_type, self.my_name, payload)
        return self._send_raw(addr, packet)

    # ---------- TIỆN ÍCH ----------

    def list_peers(self):
        return list(self.connections.keys())

    def shutdown(self):
        for addr, conn in list(self.connections.items()):
            try:
                conn.close()
            except Exception:
                pass
        self.connections.clear()
        try:
            self.server_socket.close()
        except Exception:
            pass
