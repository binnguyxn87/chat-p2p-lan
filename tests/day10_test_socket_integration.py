"""
Kiểm chứng TOÀN BỘ luồng mã hóa lai hoạt động đúng khi truyền
qua một kết nối TCP THẬT (không còn là gọi hàm nội bộ trong cùng 1 tiến trình như
tuần 1 nữa). Đây là script mô phỏng độc lập của B để kiểm tra module bảo mật đã
"sẵn sàng cho mạng" trước khi ráp with module Networking thật của A.
 
LƯU Ý QUAN TRỌNG (ghi vào báo cáo):
Đây là bài test TÍCH HỢP đầu tiên có tính chất "network thật" (dùng socket TCP
của hệ điều hành, qua địa chỉ 127.0.0.1). Khi A hoàn thiện module Networking,
phần vòng lặp gửi/nhận thô (socket.send/recv) trong file này sẽ được THAY THẾ
bằng module của A; còn toàn bộ logic bắt tay + mã hóa (protocol.py, session_manager.py,
crypto/*) được giữ nguyên không đổi - đây chính là lợi ích của việc tách module rõ ràng.
 
"""
 
import sys
import os
import socket
import threading
import time
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import aes_encrypt
from session.protocol import (
    build_pubkey_message, build_key_exchange_message, build_chat_message,
    extract_encrypted_session_key, serialize_message, parse_message,
    safe_decrypt_chat_message, MSG_TYPE_PUBKEY, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_CHAT,
)
from session.session_manager import SessionManager
from Crypto.PublicKey import RSA
 
HOST = "127.0.0.1"
PORT = 51234  # cổng riêng cho test, tránh trùng cổng hệ thống
TIN_NHAN_GUI_DI = "Tin nhắn thật gửi qua socket TCP - đã mã hóa hybrid RSA+AES!"
 
 
def chay_ben_server(ready_event: threading.Event, ket_qua: dict, loi: dict):
    """Đóng vai trò 'PeerB' - bên lắng nghe kết nối đến (giống như 1 peer đang online chờ chat)."""
    try:
        my_private, my_public = generate_rsa_keypair()
        manager = SessionManager()
        session = manager.get_or_create("peerA")
 
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        ready_event.set()  # báo cho client biết server đã sẵn sàng nhận kết nối
 
        conn, addr = srv.accept()
        print(f"[Server/PeerB] Đã chấp nhận kết nối từ {addr}")
        f = conn.makefile("r")
 
        # Bước 1: gửi public key của mình cho client
        conn.sendall((serialize_message(build_pubkey_message("peerB", my_public.export_key())) + "\n").encode())
        print("[Server/PeerB] Đã gửi public key.")
 
        # Bước 2: nhận public key của client
        msg = parse_message(f.readline())
        assert msg["type"] == MSG_TYPE_PUBKEY
        client_pub = RSA.import_key(msg["public_key_pem"])
        session.set_peer_public_key(client_pub)
        print("[Server/PeerB] Đã nhận public key của peerA.")
 
        # Bước 3: nhận session key đã mã hóa
        msg = parse_message(f.readline())
        assert msg["type"] == MSG_TYPE_KEY_EXCHANGE
        encrypted_key = extract_encrypted_session_key(msg)
        session.receive_encrypted_session_key(my_private, encrypted_key)
        print(f"[Server/PeerB] Đã giải mã session key. Trạng thái: {session.state.value}")
 
        # Bước 4: nhận tin nhắn chat đã mã hóa
        msg = parse_message(f.readline())
        assert msg["type"] == MSG_TYPE_CHAT
        plaintext = safe_decrypt_chat_message(session.session_key, msg)
        print(f"[Server/PeerB] Đã giải mã tin nhắn: \"{plaintext}\"")
        ket_qua["server_nhan_duoc"] = plaintext
 
        conn.close()
        srv.close()
    except Exception as e:
        loi["server"] = repr(e)
 
 
def chay_ben_client(ready_event: threading.Event, ket_qua: dict, loi: dict):
    """Đóng vai trò 'PeerA' - bên chủ động kết nối tới PeerB."""
    try:
        ready_event.wait(timeout=5)
        my_private, my_public = generate_rsa_keypair()
        manager = SessionManager()
        session = manager.get_or_create("peerB")
 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        f = sock.makefile("r")
        print("[Client/PeerA] Đã kết nối tới server.")
 
        # Bước 1: nhận public key của server
        msg = parse_message(f.readline())
        server_pub = RSA.import_key(msg["public_key_pem"])
        session.set_peer_public_key(server_pub)
        print("[Client/PeerA] Đã nhận public key của peerB.")
 
        # Bước 2: gửi public key của mình
        sock.sendall((serialize_message(build_pubkey_message("peerA", my_public.export_key())) + "\n").encode())
        print("[Client/PeerA] Đã gửi public key.")
 
        # Bước 3: sinh + mã hóa + gửi session key (client đóng vai trò chủ động)
        encrypted_key = session.generate_and_encrypt_session_key()
        sock.sendall((serialize_message(build_key_exchange_message("peerA", encrypted_key)) + "\n").encode())
        session.confirm_established()
        print(f"[Client/PeerA] Đã gửi session key đã mã hóa. Trạng thái: {session.state.value}")
 
        # Bước 4: gửi tin nhắn chat đã mã hóa bằng AES-GCM
        enc = aes_encrypt(session.session_key, TIN_NHAN_GUI_DI)
        sock.sendall((serialize_message(build_chat_message("peerA", enc)) + "\n").encode())
        print(f"[Client/PeerA] Đã gửi tin nhắn mã hóa: \"{TIN_NHAN_GUI_DI}\"")
        ket_qua["client_da_gui"] = TIN_NHAN_GUI_DI
 
        time.sleep(0.3)  # đợi server xử lý xong trước khi đóng socket
        sock.close()
    except Exception as e:
        loi["client"] = repr(e)
 
 
def main():
    print("=" * 60)
    print("NGÀY 10 - TÍCH HỢP MÃ HÓA LAI QUA SOCKET TCP THẬT")
    print("=" * 60)
    print(f"\nĐịa chỉ test: {HOST}:{PORT} (2 tiến trình độc lập, giao tiếp qua TCP thật)\n")
 
    ready_event = threading.Event()
    ket_qua = {}
    loi = {}
 
    t_server = threading.Thread(target=chay_ben_server, args=(ready_event, ket_qua, loi))
    t_client = threading.Thread(target=chay_ben_client, args=(ready_event, ket_qua, loi))
 
    t_server.start()
    t_client.start()
    t_server.join(timeout=10)
    t_client.join(timeout=10)
 
    print("\n" + "-" * 60)
    if loi:
        print("CÓ LỖI XẢY RA:", loi)
        sys.exit(1)
 
    assert "client_da_gui" in ket_qua and "server_nhan_duoc" in ket_qua, "Thiếu kết quả từ 1 trong 2 bên!"
    assert ket_qua["client_da_gui"] == ket_qua["server_nhan_duoc"], "Nội dung tin nhắn KHÔNG khớp!"
 
    print(f"Client đã gửi   : \"{ket_qua['client_da_gui']}\"")
    print(f"Server nhận được: \"{ket_qua['server_nhan_duoc']}\"")
    print("=> KHỚP 100% - Toàn bộ luồng bắt tay + mã hóa hoạt động đúng qua socket TCP thật.")
    print("\nKẾT QUẢ NGÀY 10: THÀNH CÔNG")
    print("=" * 60)
 
 
if __name__ == "__main__":
    main()