import socket
import threading
import time
from protocol import create_message, parse_message

BROADCAST_PORT = 6000

class Discovery:
    def __init__(self, my_name, my_listen_port, on_peer_found):
        self.my_name = my_name
        self.my_listen_port = my_listen_port
        self.on_peer_found = on_peer_found

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind(("0.0.0.0", BROADCAST_PORT))

        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def start(self):
        threading.Thread(target=self._listen_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def _listen_loop(self):
        while True:
            data, addr = self.udp_socket.recvfrom(1024)
            msg = parse_message(data.decode('utf-8'))
            if msg and msg["type"] == "PEER_ANNOUNCE":
                sender_name = msg["sender"]
                if sender_name == self.my_name:
                    continue
                tcp_port = msg["payload"]["tcp_port"]
                peer_ip = addr[0]
                self.on_peer_found(sender_name, peer_ip, tcp_port)

    def _announce_loop(self):
        while True:
            packet = create_message(
                "PEER_ANNOUNCE",
                self.my_name,
                {"tcp_port": self.my_listen_port}
            )
            self.broadcast_socket.sendto(
                packet.encode('utf-8'),
                ("255.255.255.255", BROADCAST_PORT)
            )
            time.sleep(3)