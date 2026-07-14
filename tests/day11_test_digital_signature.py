"""
Kiểm tra chữ ký số RSA hoạt động đúng, và tích hợp vào
gói tin chat_message (kết hợp với mã hóa AES-GCM tuần 1 -> "sign-then-encrypt").
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
from crypto.signature_utils import sign_message, verify_signature
from session.protocol import build_chat_message, extract_enc_dict, extract_signature, serialize_message, parse_message
 
 
def test_ky_va_xac_thuc_co_ban():
    print("=" * 60)
    print("PHẦN A - KÝ SỐ VÀ XÁC THỰC CƠ BẢN")
    print("=" * 60)
 
    a_private, a_public = generate_rsa_keypair()
    message = "Tôi xác nhận chuyển khoản 5.000.000 VND"
 
    print(f"\nTin nhắn gốc: \"{message}\"")
    signature = sign_message(a_private, message)
    print(f"Chữ ký (hex, rút gọn): {signature.hex()[:50]}...")
 
    print("\n[Test 1] Xác thực với public key ĐÚNG của người gửi (peerA)")
    hop_le = verify_signature(a_public, message, signature)
    print(f"    Kết quả: {hop_le}")
    assert hop_le is True
 
    print("\n[Test 2] Kẻ tấn công sửa nội dung SAU KHI đã ký")
    message_bi_sua = "Tôi xác nhận chuyển khoản 50.000.000 VND"  # thêm 1 số 0!
    hop_le2 = verify_signature(a_public, message_bi_sua, signature)
    print(f"    Nội dung bị sửa: \"{message_bi_sua}\"")
    print(f"    Kết quả xác thực: {hop_le2}")
    assert hop_le2 is False
    print("    -> ĐÚNG NHƯ KỲ VỌNG: phát hiện nội dung đã bị thay đổi.")
 
    print("\n[Test 3] Kẻ mạo danh dùng public key của MÌNH thay vì của peerA thật")
    _, fake_public = generate_rsa_keypair()
    hop_le3 = verify_signature(fake_public, message, signature)
    print(f"    Kết quả xác thực với public key giả mạo: {hop_le3}")
    assert hop_le3 is False
    print("    -> ĐÚNG NHƯ KỲ VỌNG: không thể giả mạo chữ ký nếu không có private key gốc.")
 
 
def test_tich_hop_sign_then_encrypt():
    print("\n" + "=" * 60)
    print("PHẦN B - TÍCH HỢP 'SIGN-THEN-ENCRYPT' VÀO GÓI TIN CHAT")
    print("=" * 60)
 
    a_private, a_public = generate_rsa_keypair()
    session_key = generate_aes_key()
    message = "Chào B, tin nhắn này vừa được ký vừa được mã hóa!"
 
    print(f"\n[Người gửi - peerA] Nội dung gốc: \"{message}\"")
    print("[Người gửi - peerA] Bước 1: Ký nội dung bằng private key của mình")
    signature = sign_message(a_private, message)
 
    print("[Người gửi - peerA] Bước 2: Mã hóa nội dung bằng AES-GCM (session key)")
    enc = aes_encrypt(session_key, message)
 
    print("[Người gửi - peerA] Bước 3: Đóng gói thành chat_message kèm chữ ký")
    msg = build_chat_message("peerA", enc, signature=signature)
    raw = serialize_message(msg)
    print(f"    Gói tin JSON (rút gọn): {raw[:100]}...")
 
    print("\n[Người nhận - peerB] Bước 1: Parse gói tin nhận được")
    parsed = parse_message(raw)
 
    print("[Người nhận - peerB] Bước 2: Giải mã bằng session key chung")
    enc_dict = extract_enc_dict(parsed)
    plaintext = aes_decrypt(session_key, enc_dict)
    print(f"    Giải mã ra: \"{plaintext}\"")
 
    print("[Người nhận - peerB] Bước 3: Xác thực chữ ký bằng public key của peerA")
    sig = extract_signature(parsed)
    hop_le = verify_signature(a_public, plaintext, sig)
    print(f"    Chữ ký hợp lệ: {hop_le}")
 
    assert plaintext == message
    assert hop_le is True
    print("\n=> Gói tin vừa được mã hóa (bí mật), vừa toàn vẹn (AES-GCM tag),")
    print("   vừa xác thực được đúng người gửi (chữ ký số) - đủ 3 thuộc tính")
    print("   bảo mật cốt lõi: Confidentiality + Integrity + Authenticity.")
 
 
if __name__ == "__main__":
    test_ky_va_xac_thuc_co_ban()
    test_tich_hop_sign_then_encrypt()
    print("\n" + "=" * 60)
    print("KẾT QUẢ NGÀY 11: THÀNH CÔNG")
    print("=" * 60)