"""
Dồn toàn bộ các tình huống LỖI có thể xảy ra trong thực tế
khi module Bảo mật hoạt động cùng module Networking (A) và UI (C), đảm bảo mọi
lỗi đều được xử lý gọn gàng bằng exception rõ ràng, KHÔNG để chương trình crash
đột ngột (rất quan trọng vì đây là ứng dụng chat chạy liên tục).
 
DANH SÁCH TÌNH HUỐNG KIỂM TRA:
  1. Gói tin JSON bị hỏng/cắt cụt giữa đường truyền
  2. Gói tin chat thiếu trường dữ liệu bắt buộc
  3. Dữ liệu base64 trong gói tin bị hỏng
  4. Giải mã bằng session key SAI (VD: bug đồng bộ giữa 2 bên)
  5. Chữ ký số không khớp (tin nhắn giả mạo / bị sửa)
  6. Gọi sai thứ tự hàm trong session_manager (chưa có public key mà đòi trao session key)
  7. Nhiều peer gửi tin nhắn xen kẽ nhau (đảm bảo không bị lẫn session key giữa các peer)
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
from crypto.signature_utils import sign_message, verify_signature
from session.protocol import (
    build_chat_message, serialize_message, parse_message,
    safe_decrypt_chat_message, CryptoProtocolError,
)
from session.session_manager import SessionManager
 
so_case_pass = 0
so_case_total = 0
 
 
def check(mo_ta, dieu_kien):
    global so_case_pass, so_case_total
    so_case_total += 1
    trang_thai = "PASS" if dieu_kien else "FAIL"
    if dieu_kien:
        so_case_pass += 1
    print(f"  [{trang_thai}] {mo_ta}")
 
 
def case_1_json_hong():
    print("\n[Tình huống 1] Gói tin JSON bị hỏng/cắt cụt")
    try:
        parse_message('{"type": "chat_message", "sender": "peerA"')  # thiếu dấu đóng
        check("Phải raise lỗi khi JSON không hợp lệ", False)
    except CryptoProtocolError:
        check("Bắt đúng CryptoProtocolError khi JSON hỏng", True)
 
 
def case_2_thieu_truong():
    print("\n[Tình huống 2] Gói tin chat thiếu trường 'payload'")
    key = generate_aes_key()
    msg = {"type": "chat_message", "sender": "peerA", "timestamp": 123}  # thiếu payload
    try:
        safe_decrypt_chat_message(key, msg)
        check("Phải raise lỗi khi thiếu trường payload", False)
    except CryptoProtocolError as e:
        check(f"Bắt đúng CryptoProtocolError khi thiếu trường ('{e}')", True)
 
 
def case_3_base64_hong():
    print("\n[Tình huống 3] Dữ liệu base64 trong gói tin bị hỏng")
    key = generate_aes_key()
    enc = aes_encrypt(key, "test")
    msg = build_chat_message("peerA", enc)
    msg["payload"]["ciphertext"] = "!!!khong-phai-base64-hop-le!!!"
    try:
        safe_decrypt_chat_message(key, msg)
        check("Phải raise lỗi khi base64 hỏng", False)
    except CryptoProtocolError as e:
        check(f"Bắt đúng CryptoProtocolError khi base64 hỏng ('{str(e)[:40]}...')", True)
 
 
def case_4_sai_session_key():
    print("\n[Tình huống 4] Giải mã bằng session key SAI")
    key_dung = generate_aes_key()
    key_sai = generate_aes_key()
    enc = aes_encrypt(key_dung, "Nội dung bí mật")
    msg = build_chat_message("peerA", enc)
    try:
        safe_decrypt_chat_message(key_sai, msg)
        check("Phải raise lỗi khi dùng sai session key", False)
    except CryptoProtocolError as e:
        check(f"Bắt đúng CryptoProtocolError khi sai session key ('{str(e)[:40]}...')", True)
 
 
def case_5_chu_ky_khong_khop():
    print("\n[Tình huống 5] Chữ ký số không khớp với người gửi thật")
    real_private, real_public = generate_rsa_keypair()
    _, fake_public = generate_rsa_keypair()
    message = "Nội dung quan trọng"
    signature = sign_message(real_private, message)
    ket_qua = verify_signature(fake_public, message, signature)
    check("verify_signature trả về False khi dùng sai public key", ket_qua is False)
 
 
def case_6_sai_thu_tu_goi_ham():
    print("\n[Tình huống 6] Gọi trao session key TRƯỚC khi có public key của peer")
    manager = SessionManager()
    session = manager.get_or_create("peerX")
    try:
        session.generate_and_encrypt_session_key()  # chưa set_peer_public_key()!
        check("Phải raise lỗi khi chưa có public key của peer", False)
    except RuntimeError as e:
        check(f"Bắt đúng RuntimeError với thông báo rõ ràng ('{str(e)[:50]}...')", True)
 
 
def case_7_nhieu_peer_khong_lan():
    print("\n[Tình huống 7] Nhiều peer gửi tin nhắn xen kẽ - session key không bị lẫn")
    manager = SessionManager()
    peers_data = {}
 
    for peer_id in ["peerA", "peerC", "peerD"]:
        s = manager.get_or_create(peer_id)
        _, pub = generate_rsa_keypair()
        s.set_peer_public_key(pub)
        s.generate_and_encrypt_session_key()
        s.confirm_established()
        peers_data[peer_id] = f"Tin nhắn bí mật riêng cho {peer_id}"
 
    # Mã hóa tin nhắn riêng cho từng peer bằng ĐÚNG session key của peer đó
    encrypted_msgs = {}
    for peer_id, plaintext in peers_data.items():
        session = manager.get_or_create(peer_id)
        encrypted_msgs[peer_id] = aes_encrypt(session.session_key, plaintext)
 
    # Giải mã lại và đảm bảo không có sự nhầm lẫn chéo giữa các peer
    tat_ca_dung = True
    for peer_id, plaintext_goc in peers_data.items():
        session = manager.get_or_create(peer_id)
        giai_ma = aes_decrypt(session.session_key, encrypted_msgs[peer_id])
        if giai_ma != plaintext_goc:
            tat_ca_dung = False
 
    check("Giải mã đúng tin nhắn cho từng peer, không bị lẫn session key", tat_ca_dung)
 
    # Thử cố tình dùng NHẦM session key của peer khác để giải mã -> phải thất bại
    try:
        session_A = manager.get_or_create("peerA")
        session_C = manager.get_or_create("peerC")
        aes_decrypt(session_C.session_key, encrypted_msgs["peerA"])
        check("Phải thất bại khi dùng session key của peerC để giải mã tin của peerA", False)
    except ValueError:
        check("Đúng như kỳ vọng: không thể dùng session key của peer khác để giải mã", True)
 
 
def main():
    print("=" * 60)
    print("NGÀY 13 - KIỂM THỬ TOÀN DIỆN CÁC TÌNH HUỐNG LỖI")
    print("=" * 60)
 
    case_1_json_hong()
    case_2_thieu_truong()
    case_3_base64_hong()
    case_4_sai_session_key()
    case_5_chu_ky_khong_khop()
    case_6_sai_thu_tu_goi_ham()
    case_7_nhieu_peer_khong_lan()
 
    print("\n" + "=" * 60)
    print(f"KẾT QUẢ NGÀY 13: {so_case_pass}/{so_case_total} tình huống xử lý đúng")
    if so_case_pass == so_case_total:
        print("=> TẤT CẢ TÌNH HUỐNG LỖI ĐỀU ĐƯỢC XỬ LÝ AN TOÀN, KHÔNG CRASH.")
    print("=" * 60)
    assert so_case_pass == so_case_total, "Có tình huống chưa xử lý đúng!"
 
 
if __name__ == "__main__":
    main()
 