"""
day3_test_rsa_encrypt.py
Việc cần làm trong ngày 3: Test mã hóa/giải mã RSA, và CHỨNG MINH bằng thực nghiệm
lý do vì sao cần mã hóa lai (hybrid) - đây là bằng chứng thực nghiệm quan trọng cho báo cáo.
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt, max_encryptable_bytes
)
 
 
def main():
    print("=" * 60)
    print("NGÀY 3 - TEST MÃ HÓA/GIẢI MÃ RSA")
    print("=" * 60)
 
    private_key, public_key = generate_rsa_keypair()
 
    # --- Test 1: Mã hóa dữ liệu nhỏ (giống kích thước 1 khóa AES-256 = 32 byte) ---
    print("\n[TEST 1] Mã hóa dữ liệu nhỏ (32 byte, giống kích thước khóa AES phiên)")
    fake_session_key = os.urandom(32)
    print(f"    Dữ liệu gốc (hex): {fake_session_key.hex()}")
 
    encrypted = rsa_encrypt(public_key, fake_session_key)
    print(f"    Đã mã hóa (hex, rút gọn): {encrypted.hex()[:50]}...")
 
    decrypted = rsa_decrypt(private_key, encrypted)
    assert decrypted == fake_session_key
    print("    -> Giải mã khớp 100% với bản gốc. OK.")
 
    # --- Test 2: Chứng minh giới hạn kích thước của RSA ---
    print("\n[TEST 2] Kiểm tra giới hạn kích thước dữ liệu mà RSA-2048 OAEP mã hóa được")
    limit = max_encryptable_bytes()
    print(f"    Giới hạn lý thuyết (công thức OAEP): {limit} byte")
 
    print(f"\n    Thử mã hóa dữ liệu đúng bằng giới hạn ({limit} byte)...")
    try:
        rsa_encrypt(public_key, os.urandom(limit))
        print(f"    -> Thành công (đúng như dự đoán).")
    except Exception as e:
        print(f"    -> Thất bại: {e}")
 
    over_limit = limit + 1
    print(f"\n    Thử mã hóa dữ liệu VƯỢT giới hạn 1 byte ({over_limit} byte)...")
    try:
        rsa_encrypt(public_key, os.urandom(over_limit))
        print("    -> [KHÔNG MONG ĐỢI] Mã hóa thành công?!")
    except ValueError as e:
        print(f"    -> Thất bại như dự đoán. Lỗi: '{e}'")
        print("    => KẾT LUẬN QUAN TRỌNG CHO BÁO CÁO:")
        print("       RSA-2048 KHÔNG THỂ mã hóa trực tiếp một tin nhắn chat thông")
        print("       thường (thường dài hơn 214 byte). Đây chính là lý do bắt buộc")
        print("       phải dùng kiến trúc mã hóa LAI: RSA chỉ mã hóa khóa AES phiên")
        print("       (32 byte, nằm trong giới hạn), còn AES mã hóa toàn bộ nội dung")
        print("       tin nhắn (không giới hạn độ dài, tốc độ nhanh hơn RSA rất nhiều).")
 
    print("\nKẾT QUẢ NGÀY 3: THÀNH CÔNG")
    print("=" * 60)
 
 
if __name__ == "__main__":
    main()