"""
Việc cần làm : Bài test "tổng duyệt" cuối cùng của module Bảo mật trước khi
ráp với code thật của A và C. Mô phỏng ĐÚNG kịch bản thực tế nhất có thể:
  - 3 "máy" chạy đồng thời (khớp đúng số thành viên nhóm: giống việc 3 người
    dùng cùng mở ứng dụng chat và kết nối với nhau qua LAN)
  - Mỗi cặp máy bắt tay qua socket TCP thật, có TOFU fingerprint check
  - Tin nhắn được ký số + mã hóa AES-GCM
  - Mô phỏng 1 máy bị rớt mạng giữa chừng và kết nối lại

Đây là bài test tổng hợp TẤT CẢ những gì đã xây dựng trong 3 tuần: rsa_utils,
aes_utils, protocol, session_manager, signature_utils, fingerprint_utils, trust_store.
"""

import sys
import os
import socket
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import aes_encrypt
from crypto.signature_utils import sign_message, verify_signature
from crypto.protocol import (
    build_pubkey_message, build_key_exchange_message, build_chat_message,
    extract_encrypted_session_key, extract_signature, serialize_message, parse_message,
    safe_decrypt_chat_message, MSG_TYPE_PUBKEY, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_CHAT,
)
from session.session_manager import SessionManager
from trust.trust_store import TrustStore, TrustDecision
from Crypto.PublicKey import RSA

BASE_PORT = 51300
TRUST_STORE_PATH = os.path.join(os.path.dirname(__file__), "..", "trust", "known_peers_rehearsal.json")


class MayAo:
    """Mô phỏng 1 'máy' hoàn chỉnh chạy ứng dụng chat - tự có khóa RSA riêng,
    SessionManager riêng, TrustStore riêng, y hệt 1 người dùng thực tế."""

    def __init__(self, ten: str, cong_lang_nghe: int):
        self.ten = ten
        self.cong = cong_lang_nghe
        self.private_key, self.public_key = generate_rsa_keypair()
        self.manager = SessionManager()
        self.tin_nhan_da_nhan = []
        self.loi = []

    def lang_nghe(self, ready_event: threading.Event, so_ket_noi_cho_doi: int):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.cong))
        srv.listen(so_ket_noi_cho_doi)
        ready_event.set()

        for _ in range(so_ket_noi_cho_doi):
            try:
                conn, _ = srv.accept()
                threading.Thread(target=self._xu_ly_ket_noi_den, args=(conn,)).start()
            except Exception as e:
                self.loi.append(f"[{self.ten}] Lỗi accept: {e}")
        time.sleep(1.5)
        srv.close()

    def _xu_ly_ket_noi_den(self, conn):
        try:
            f = conn.makefile("r")
            conn.sendall((serialize_message(build_pubkey_message(self.ten, self.public_key.export_key())) + "\n").encode())

            msg = parse_message(f.readline())
            peer_id = msg["sender"]
            session = self.manager.get_or_create(peer_id)
            peer_pub = RSA.import_key(msg["public_key_pem"])
            session.set_peer_public_key(peer_pub)

            msg = parse_message(f.readline())
            if msg["type"] == MSG_TYPE_KEY_EXCHANGE:
                encrypted_key = extract_encrypted_session_key(msg)
                session.receive_encrypted_session_key(self.private_key, encrypted_key)

            while True:
                line = f.readline()
                if not line:
                    break
                msg = parse_message(line)
                if msg["type"] == MSG_TYPE_CHAT:
                    plaintext = safe_decrypt_chat_message(session.session_key, msg)
                    sig = extract_signature(msg)
                    chu_ky_hop_le = verify_signature(peer_pub, plaintext, sig) if sig else None
                    self.tin_nhan_da_nhan.append((peer_id, plaintext, chu_ky_hop_le))
        except Exception as e:
            self.loi.append(f"[{self.ten}] Lỗi xử lý kết nối đến: {e}")

    def ket_noi_toi(self, peer_ten: str, peer_cong: int, tin_nhan_gui: str):
        try:
            session = self.manager.get_or_create(peer_ten)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", peer_cong))
            f = sock.makefile("r")

            msg = parse_message(f.readline())
            peer_pub = RSA.import_key(msg["public_key_pem"])
            session.set_peer_public_key(peer_pub)

            sock.sendall((serialize_message(build_pubkey_message(self.ten, self.public_key.export_key())) + "\n").encode())

            encrypted_key = session.generate_and_encrypt_session_key()
            sock.sendall((serialize_message(build_key_exchange_message(self.ten, encrypted_key)) + "\n").encode())
            session.confirm_established()

            enc = aes_encrypt(session.session_key, tin_nhan_gui)
            signature = sign_message(self.private_key, tin_nhan_gui)
            sock.sendall((serialize_message(build_chat_message(self.ten, enc, signature=signature)) + "\n").encode())

            time.sleep(0.3)
            sock.close()
        except Exception as e:
            self.loi.append(f"[{self.ten}] Lỗi kết nối tới {peer_ten}: {e}")


def main():
    print("=" * 60)
    print("NGÀY 19 - DIỄN TẬP TÍCH HỢP TOÀN HỆ THỐNG (3 PEER ĐỒNG THỜI)")
    print("=" * 60)

    if os.path.exists(TRUST_STORE_PATH):
        os.remove(TRUST_STORE_PATH)

    may_A = MayAo("peerA", BASE_PORT + 0)
    may_B = MayAo("peerB", BASE_PORT + 1)
    may_C = MayAo("peerC", BASE_PORT + 2)
    tat_ca_may = [may_A, may_B, may_C]

    print(f"\n[Thiết lập] Khởi động 3 máy ảo, mỗi máy tự sinh khóa RSA riêng:")
    for m in tat_ca_may:
        print(f"    {m.ten} lắng nghe tại cổng {m.cong}")

    print("\n[Kịch bản] peerA và peerC đều chủ động kết nối tới peerB")
    print("           (mô phỏng peerB đang là người vừa mở app, 2 bạn còn lại nhắn tới)")

    ready_B = threading.Event()
    t_B_listen = threading.Thread(target=may_B.lang_nghe, args=(ready_B, 2))
    t_B_listen.start()
    ready_B.wait(timeout=5)

    t_A = threading.Thread(target=may_A.ket_noi_toi, args=("peerB", may_B.cong, "Chào B, A đây! (tin nhắn 1)"))
    t_C = threading.Thread(target=may_C.ket_noi_toi, args=("peerB", may_B.cong, "Chào B, C đây! (tin nhắn 1)"))
    t_A.start(); t_C.start()
    t_A.join(timeout=5); t_C.join(timeout=5)
    t_B_listen.join(timeout=5)

    print(f"\n[Kiểm tra] peerB đã nhận được bao nhiêu tin nhắn?")
    print(f"    Số tin nhắn nhận được: {len(may_B.tin_nhan_da_nhan)}")
    for peer_id, plaintext, chu_ky_hop_le in may_B.tin_nhan_da_nhan:
        print(f"    - Từ {peer_id}: \"{plaintext}\" (chữ ký hợp lệ: {chu_ky_hop_le})")

    assert len(may_B.tin_nhan_da_nhan) == 2, f"Lỗi: peerB phải nhận đúng 2 tin nhắn, thực tế {len(may_B.tin_nhan_da_nhan)}"
    assert all(chu_ky_hop_le is True for _, _, chu_ky_hop_le in may_B.tin_nhan_da_nhan)
    print("    -> peerB nhận đúng 2 tin nhắn từ 2 peer khác nhau, cả 2 chữ ký đều hợp lệ. OK.")

    print("\n[Kiểm tra fingerprint - TOFU] Ghi nhận fingerprint của peerA và peerC vào TrustStore")
    trust_store = TrustStore(TRUST_STORE_PATH)
    session_voi_A = may_B.manager.get_or_create("peerA")
    session_voi_C = may_B.manager.get_or_create("peerC")
    qd_A, _, _ = trust_store.check_and_update("peerA", session_voi_A.peer_public_key.export_key())
    qd_C, _, _ = trust_store.check_and_update("peerC", session_voi_C.peer_public_key.export_key())
    print(f"    Quyết định TOFU cho peerA: {qd_A}")
    print(f"    Quyết định TOFU cho peerC: {qd_C}")
    assert qd_A == TrustDecision.NEW and qd_C == TrustDecision.NEW
    print("    -> Cả 2 peer đều được ghi nhận lần đầu đúng như kỳ vọng. OK.")

    print("\n[Mô phỏng sự cố] peerA đột ngột rớt mạng giữa cuộc trò chuyện với peerB")
    session_voi_A.invalidate()
    print(f"    Trạng thái session (B nhìn A) sau invalidate: {session_voi_A.state.value}")
    assert not session_voi_A.is_ready()

    print("\n[Kết nối lại] peerA kết nối lại với peerB - phải bắt tay lại từ đầu")
    ready_B2 = threading.Event()
    t_B_listen2 = threading.Thread(target=may_B.lang_nghe, args=(ready_B2, 1))
    t_B_listen2.start()
    ready_B2.wait(timeout=5)
    t_A2 = threading.Thread(target=may_A.ket_noi_toi, args=("peerB", may_B.cong, "B ơi, A vừa kết nối lại nè!"))
    t_A2.start()
    t_A2.join(timeout=5)
    t_B_listen2.join(timeout=5)

    session_voi_A_sau = may_B.manager.get_or_create("peerA")
    print(f"    Trạng thái sau khi kết nối lại: {session_voi_A_sau.state.value}")
    assert session_voi_A_sau.is_ready()
    assert len(may_B.tin_nhan_da_nhan) == 3
    print(f"    -> peerB nhận thêm tin nhắn thứ 3 sau khi peerA kết nối lại thành công. OK.")

    if may_A.loi or may_B.loi or may_C.loi:
        print("\nCÓ LỖI PHÁT SINH:", may_A.loi + may_B.loi + may_C.loi)
        sys.exit(1)

    os.remove(TRUST_STORE_PATH)
    print("\n" + "=" * 60)
    print("KẾT QUẢ NGÀY 19: THÀNH CÔNG")
    print("Module Bảo mật đã sẵn sàng 100% để ráp nối với module Networking (A)")
    print("và module UI (C) thật trong bản demo cuối kỳ.")
    print("=" * 60)


if __name__ == "__main__":
    main()
