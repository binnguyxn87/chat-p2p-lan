import socket
import threading
import time
from protocol import create_message, parse_message

BROADCAST_PORT = 6001


class Discovery:
    def __init__(self, my_name, my_listen_port, on_peer_found):
        self.my_name = my_name
        self.my_listen_port = my_listen_port
        self.on_peer_found = on_peer_found
        self._running = True

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind(("0.0.0.0", BROADCAST_PORT))

        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def start(self):
        threading.Thread(target=self._listen_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def stop(self):
        self._running = False
        try:
            self.udp_socket.close()
        except Exception:
            pass

    def _listen_loop(self):
        while self._running:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
            except OSError:
                break
            msg = parse_message(data.decode('utf-8'))
            if msg and msg["type"] == "PEER_ANNOUNCE":
                sender_name = msg["sender"]
                if sender_name == self.my_name:
                    continue
                tcp_port = msg["payload"]["tcp_port"]
                peer_ip = addr[0]
                # Quy tắc tie-breaking: chỉ bên có cổng NHỎ HƠN mới chủ động
                # kết nối, tránh 2 bên cùng lúc connect() lẫn nhau -> kết nối trùng.
                if self.my_listen_port < tcp_port:
                    self.on_peer_found(sender_name, peer_ip, tcp_port)

    def _announce_loop(self):
        while self._running:
            packet = create_message(
                "PEER_ANNOUNCE",
                self.my_name,
                {"tcp_port": self.my_listen_port}
            )
            try:
                self.broadcast_socket.sendto(
                    packet.encode('utf-8'),
                    ("255.255.255.255", BROADCAST_PORT)
                )
            except OSError:
                pass
            time.sleep(3)
