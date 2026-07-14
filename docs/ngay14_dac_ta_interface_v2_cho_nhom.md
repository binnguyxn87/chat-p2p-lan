Đặc tả Interface Module Bảo mật — Bản v2 (cập nhật sau Tuần 2)


Bổ sung so với bản v1 (tuần 1): thêm protocol.py, session_manager.py, signature_utils.py,
fingerprint_utils.py. Đây là bộ hàm ĐẦY ĐỦ mà A và C sẽ dùng để ráp nối trong Tuần 3.



1. Điểm quan trọng nhất: A KHÔNG cần tự viết code mã hóa nữa

Toàn bộ phần "khó" (mã hóa, đóng gói JSON, quản lý session) đã được B đóng gói sẵn.
Việc của A ở Tuần 3 chỉ là: khi socket nhận được 1 dòng dữ liệu (text), gọi đúng hàm dưới
đây theo thứ tự — không cần hiểu chi tiết bên trong RSA/AES hoạt động ra sao.

2. Luồng tích hợp đề xuất cho A (Networking)

pythonfrom crypto.rsa_utils import generate_rsa_keypair
from crypto.protocol import (
    build_pubkey_message, build_key_exchange_message, build_chat_message,
    extract_encrypted_session_key, serialize_message, parse_message,
    safe_decrypt_chat_message, CryptoProtocolError,
    MSG_TYPE_PUBKEY, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_CHAT,
)
from crypto.aes_utils import aes_encrypt
from crypto.signature_utils import sign_message, verify_signature
from crypto.fingerprint_utils import get_public_key_fingerprint
from session.session_manager import SessionManager
from Crypto.PublicKey import RSA

# --- Khởi tạo 1 lần khi ứng dụng chạy ---
my_private, my_public = generate_rsa_keypair()
manager = SessionManager()

# --- Khi có peer mới kết nối (A gọi khi socket accept() hoặc connect() thành công) ---
session = manager.get_or_create(peer_id)
# gửi đi: serialize_message(build_pubkey_message(my_id, my_public.export_key()))

# --- Khi nhận được 1 dòng dữ liệu từ socket (A gọi hàm này trong vòng lặp recv) ---
def xu_ly_du_lieu_nhan_duoc(peer_id, raw_line):
    try:
        msg = parse_message(raw_line)
    except CryptoProtocolError as e:
        print("Gói tin lỗi, bỏ qua:", e)
        return

    session = manager.get_or_create(peer_id)

    if msg["type"] == MSG_TYPE_PUBKEY:
        peer_pub = RSA.import_key(msg["public_key_pem"])
        session.set_peer_public_key(peer_pub)
        # (Tùy chọn - khuyến nghị) hiển thị fingerprint cho C để show lên UI:
        fingerprint = get_public_key_fingerprint(peer_pub.export_key())
        # Nếu đây là bên chủ động, có thể trao session key ngay tại đây:
        # encrypted = session.generate_and_encrypt_session_key()
        # gửi đi: serialize_message(build_key_exchange_message(my_id, encrypted))
        # session.confirm_established()

    elif msg["type"] == MSG_TYPE_KEY_EXCHANGE:
        encrypted_key = extract_encrypted_session_key(msg)
        session.receive_encrypted_session_key(my_private, encrypted_key)

    elif msg["type"] == MSG_TYPE_CHAT:
        try:
            plaintext = safe_decrypt_chat_message(session.session_key, msg)
            # đưa plaintext này cho C hiển thị lên khung chat
        except CryptoProtocolError as e:
            print("Không giải mã được tin nhắn:", e)

# --- Khi peer ngắt kết nối (A gọi khi socket bị đóng/lỗi) ---
def khi_peer_ngat_ket_noi(peer_id):
    session = manager.get_or_create(peer_id)
    session.invalidate()  # bắt buộc bắt tay lại khi kết nối lại, không tái sử dụng khóa cũ

# --- Khi người dùng gõ tin nhắn để gửi đi ---
def gui_tin_nhan(peer_id, noi_dung: str):
    session = manager.get_or_create(peer_id)
    if not session.is_ready():
        raise RuntimeError("Chưa hoàn tất bắt tay với peer này, chưa thể gửi tin nhắn.")
    enc = aes_encrypt(session.session_key, noi_dung)
    # (Tùy chọn) ký số để tăng xác thực:
    signature = sign_message(my_private, noi_dung)
    msg = build_chat_message(my_id, enc, signature=signature)
    return serialize_message(msg)  # A gửi chuỗi này qua socket (nhớ thêm "\n" ở cuối)

3. Điểm quan trọng cho C (UI)


Fingerprint: khi 2 người chat lần đầu, gọi get_public_key_fingerprint() và hiển thị
lên UI (VD: dưới tên peer, dạng "Mã xác thực: 3f2a 9c1d ..."). Gợi ý thêm dòng chú thích nhỏ:
"So sánh mã này với người kia qua kênh khác để đảm bảo không bị nghe lén."
Trạng thái phiên: có thể hỏi session.is_ready() để quyết định có cho phép người dùng
gõ tin nhắn hay không (VD: disable ô nhập liệu cho tới khi bắt tay xong).
Lỗi giải mã: nếu bắt được CryptoProtocolError, hiển thị dạng thông báo hệ thống trong
khung chat, KHÔNG hiển thị chi tiết kỹ thuật cho người dùng cuối (chi tiết đó chỉ nên log
ra console để debug).


4. Danh sách toàn bộ hàm public tính đến hết Tuần 2

FileHàmMô tả ngắncrypto/rsa_utils.pygenerate_rsa_keypair(), save_key_to_file(), load_key_from_file(), rsa_encrypt(), rsa_decrypt()Sinh/lưu/đọc khóa RSA, mã hóa khóa phiêncrypto/aes_utils.pygenerate_aes_key(), aes_encrypt(), aes_decrypt()Mã hóa nội dung tin nhắncrypto/signature_utils.pysign_message(), verify_signature()Ký số & xác thực người gửicrypto/fingerprint_utils.pyget_public_key_fingerprint(), so_sanh_fingerprint()Xác thực thủ công chống MITMcrypto/protocol.pybuild_*_message(), extract_*(), serialize_message(), parse_message(), safe_decrypt_chat_message()Đóng gói/giải gói JSON để gửi qua socketsession/session_manager.pySessionManager, PeerSessionQuản lý trạng thái bắt tay & session key cho nhiều peer

5. Việc cần làm ở Tuần 3 (xem trước)


Merge nhánh Git của A (networking thật) với các hàm trên — thay socket demo tạm ở
day10_test_socket_integration.py bằng module Networking chính thức.
Kiểm thử bảo mật bằng Wireshark để có bằng chứng trực quan cho báo cáo (chứng minh
gói tin bắt được trên đường truyền là dữ liệu đã mã hóa, không đọc được plaintext).
Cùng C hoàn thiện hiển thị fingerprint + trạng thái phiên trên giao diện thật