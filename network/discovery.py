import socket
import threading
import time
from protocol import create_message, parse_message

BROADCAST_PORT = 6000   # cổng RIÊNG cho việc khám phá, khác với cổng chat TCP

class Discovery:
    def __init__(self, my_name, my_listen_port, on_peer_found):
        """
        my_name: tên của peer này
        my_listen_port: cổng TCP mà Peer đang lắng nghe (để thông báo cho người khác biết)
        on_peer_found: hàm callback, được gọi khi phát hiện 1 peer mới
                        dạng: on_peer_found(peer_name, ip, tcp_port)
        """
        self.my_name = my_name
        self.my_listen_port = my_listen_port
        self.on_peer_found = on_peer_found

        # Socket UDP để LẮNG NGHE thông báo từ peer khác
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind(("0.0.0.0", BROADCAST_PORT))

        # Socket UDP RIÊNG để GỬI broadcast (bật quyền broadcast)
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def start(self):
        """Bắt đầu 2 việc song song: lắng nghe + tự động hô to định kỳ"""
        threading.Thread(target=self._listen_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def _listen_loop(self):
        """Liên tục lắng nghe thông báo UDP từ các peer khác trong LAN"""
        while True:
            data, addr = self.udp_socket.recvfrom(1024)
            msg = parse_message(data.decode('utf-8'))
            if msg and msg["type"] == "PEER_ANNOUNCE":
                sender_name = msg["sender"]
                if sender_name == self.my_name:
                    continue   # bỏ qua thông báo của chính mình
                tcp_port = msg["payload"]["tcp_port"]
                peer_ip = addr[0]
                self.on_peer_found(sender_name, peer_ip, tcp_port)

    def _announce_loop(self):
        """Cứ mỗi vài giây, hô to 1 lần để peer khác biết mình đang tồn tại"""
        while True:
            packet = create_message(
                "PEER_ANNOUNCE",
                self.my_name,
                {"tcp_port": self.my_listen_port}
            )
            self.broadcast_socket.sendto(
                packet.encode('utf-8'),
                ("255.255.255.255", BROADCAST_PORT)   # địa chỉ broadcast toàn mạng LAN
            )
            time.sleep(3)   # 3 giây hô 1 lần