"""
 Xây dựng và kiểm tra lớp "đóng gói" dữ liệu mã hóa thành JSON
để chuẩn bị truyền qua socket mạng thật (sẽ dùng ở Ngày 10).
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt
from crypto.aes_utils import generate_aes_key, aes_encrypt
from session.protocol import (
    build_pubkey_message, build_key_exchange_message, build_chat_message,
    extract_encrypted_session_key, extract_enc_dict, extract_signature,
    serialize_message, parse_message, CryptoProtocolError,
)
from Crypto.PublicKey import RSA
 
 
def main():
    print("=" * 60)
    print("NGÀY 8 - TEST ĐÓNG GÓI / GIẢI GÓI TIN (PROTOCOL)")
    print("=" * 60)
 
    private_key, public_key = generate_rsa_keypair()
 
    # --- Test 1: Gói tin trao đổi public key ---
    print("\n[TEST 1] Gói tin pubkey_exchange")
    msg1 = build_pubkey_message("peerB", public_key.export_key())
    raw1 = serialize_message(msg1)
    print(f"    JSON gửi đi (rút gọn): {raw1[:90]}...")
    parsed1 = parse_message(raw1)
    khoi_phuc_key = RSA.import_key(parsed1["public_key_pem"])
    assert khoi_phuc_key.export_key() == public_key.export_key()
    print("    -> Parse lại đúng, khôi phục public key khớp 100%. OK.")
 
    # --- Test 2: Gói tin trao session key ---
    print("\n[TEST 2] Gói tin key_exchange")
    session_key = generate_aes_key()
    encrypted_key = rsa_encrypt(public_key, session_key)
    msg2 = build_key_exchange_message("peerA", encrypted_key)
    raw2 = serialize_message(msg2)
    print(f"    JSON gửi đi (rút gọn): {raw2[:90]}...")
    parsed2 = parse_message(raw2)
    khoi_phuc_encrypted_key = extract_encrypted_session_key(parsed2)
    assert khoi_phuc_encrypted_key == encrypted_key
    print("    -> Parse lại đúng, encrypted_session_key khớp 100%. OK.")
 
    # --- Test 3: Gói tin chat message ---
    print("\n[TEST 3] Gói tin chat_message")
    enc = aes_encrypt(session_key, "Tin nhắn test đóng gói giao thức")
    msg3 = build_chat_message("peerA", enc)
    raw3 = serialize_message(msg3)
    print(f"    JSON gửi đi (rút gọn): {raw3[:90]}...")
    parsed3 = parse_message(raw3)
    khoi_phuc_enc = extract_enc_dict(parsed3)
    assert khoi_phuc_enc == enc
    assert extract_signature(parsed3) is None  # chưa có chữ ký ở test này
    print("    -> Parse lại đúng, enc_dict khớp 100%, chưa có chữ ký (đúng như thiết kế). OK.")
 
    # --- Test 4: Gói tin lỗi (JSON hỏng) phải bị bắt đúng loại lỗi ---
    print("\n[TEST 4] Gói tin JSON bị hỏng (mô phỏng lỗi đường truyền)")
    corrupted = raw3[:len(raw3)//2]  # cắt cụt gói tin giữa chừng
    try:
        parse_message(corrupted)
        print("    -> [KHÔNG MONG ĐỢI] Parse thành công dữ liệu hỏng?!")
    except CryptoProtocolError as e:
        print(f"    -> Bắt đúng lỗi CryptoProtocolError: '{e}'")
        print("    -> ĐÚNG NHƯ KỲ VỌNG: C (UI) chỉ cần bắt 1 loại exception này.")
 
    print("\nKẾT QUẢ NGÀY 8: THÀNH CÔNG - Giao thức đóng gói hoạt động đúng")
    print("=" * 60)
 
 
if __name__ == "__main__":
    main()