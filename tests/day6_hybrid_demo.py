"""
day6_hybrid_demo.py
Ghép RSA + AES thành demo mô phỏng ĐẦY ĐỦ luồng mã hóa lai
giữa 2 "peer" (mô phỏng, chưa qua socket mạng thật - việc đó sẽ tích hợp ở tuần 2-3
cùng module Networking của bạn A).
 
LUỒNG HOẠT ĐỘNG :
  1. Peer B sinh cặp khóa RSA, "công bố" public key (giả lập gửi cho Peer A).
  2. Peer A sinh khóa AES phiên (session key) ngẫu nhiên.
  3. Peer A mã hóa session key bằng RSA public key của Peer B -> gửi đi.
  4. Peer B dùng RSA private key giải mã, lấy được session key.
  5. Từ đây, cả 2 bên dùng chung session key để mã hóa/giải mã tin nhắn bằng AES
     (nhanh hơn RSA rất nhiều - xem kết quả benchmark ngày 5).
  6. Minh họa thêm: giả lập kẻ tấn công chặn gói tin giữa đường, chứng minh
     không đọc được nội dung nếu không có session key.
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
 
 
def line():
    print("-" * 60)
 
 
def main():
    print("=" * 60)
    print("NGÀY 6 - DEMO ĐẦY ĐỦ LUỒNG MÃ HÓA LAI (HYBRID) RSA + AES")
    print("=" * 60)
 
    # ----- BƯỚC 1 -----
    print("\n[BƯỚC 1] Peer B sinh cặp khóa RSA và công bố public key")
    line()
    b_private, b_public = generate_rsa_keypair()
    print("[Peer B] Đã sinh khóa RSA 2048-bit.")
    print("[Peer B] --(gửi public key)--> Peer A")
 
    # ----- BƯỚC 2 -----
    print("\n[BƯỚC 2] Peer A sinh khóa AES phiên (session key) ngẫu nhiên")
    line()
    session_key = generate_aes_key()
    print(f"[Peer A] Session key vừa tạo (hex): {session_key.hex()}")
 
    # ----- BƯỚC 3 -----
    print("\n[BƯỚC 3] Peer A mã hóa session key bằng RSA public key của Peer B")
    line()
    encrypted_session_key = rsa_encrypt(b_public, session_key)
    print(f"[Peer A] Session key sau khi mã hóa RSA (hex, rút gọn):")
    print(f"         {encrypted_session_key.hex()[:70]}...")
    print("[Peer A] --(gửi session key đã mã hóa)--> Peer B")
 
    # ----- BƯỚC 4 -----
    print("\n[BƯỚC 4] Peer B dùng RSA private key giải mã để lấy session key")
    line()
    decrypted_session_key = rsa_decrypt(b_private, encrypted_session_key)
    assert decrypted_session_key == session_key, "LỖI NGHIÊM TRỌNG: session key không khớp!"
    print(f"[Peer B] Giải mã thành công. Session key: {decrypted_session_key.hex()}")
    print("[Peer B] -> Khớp 100% với session key gốc của Peer A. Trao khóa an toàn!")
 
    # ----- BƯỚC 5 -----
    print("\n[BƯỚC 5] Hai bên dùng chung session key để chat (mã hóa bằng AES-GCM)")
    line()
    cuoc_hoi_thoai = [
        ("Peer A", "Chào B, mình là A đây!"),
        ("Peer B", "Chào A, kênh chat đã được mã hóa an toàn rồi nhé."),
        ("Peer A", "Tuyệt vời, vậy giờ mình có thể trao đổi nội dung nhạy cảm."),
    ]
 
    for sender, msg in cuoc_hoi_thoai:
        key_dung = session_key if sender == "Peer A" else decrypted_session_key
        enc = aes_encrypt(key_dung, msg)
        print(f"\n[{sender} gửi]   Bản rõ    : \"{msg}\"")
        print(f"{'':11}Bản mã hóa: {enc['ciphertext'].hex()[:50]}...")
 
        # Bên nhận giải mã bằng session key của mình (đã đồng bộ ở bước 4)
        key_nhan = decrypted_session_key if sender == "Peer A" else session_key
        dec = aes_decrypt(key_nhan, enc)
        nguoi_nhan = "Peer B" if sender == "Peer A" else "Peer A"
        print(f"[{nguoi_nhan} nhận]  Giải mã   : \"{dec}\"")
        assert dec == msg
 
    # ----- BƯỚC 6 -----
    print("\n\n[BƯỚC 6] Giả lập kẻ tấn công chặn gói tin giữa đường (không có session key)")
    line()
    msg_bi_chan = "Mật khẩu ngân hàng của tôi là: xyz123"
    enc = aes_encrypt(session_key, msg_bi_chan)
    print(f"[Peer A gửi] Bản rõ thật: \"{msg_bi_chan}\"")
    print(f"[Kẻ tấn công chặn được] Chỉ thấy dữ liệu mã hóa (vô nghĩa):")
    print(f"    {enc['ciphertext'].hex()}")
    print(f"[Kẻ tấn công] Không có session key -> KHÔNG THỂ giải mã, dữ liệu an toàn.")
 
    print("\n" + "=" * 60)
    print("KẾT QUẢ NGÀY 6: THÀNH CÔNG - Luồng mã hóa lai hoạt động đúng hoàn toàn")
    print("=" * 60)
 
 
if __name__ == "__main__":
    main()