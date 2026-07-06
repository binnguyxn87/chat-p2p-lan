"""
day4_test_aes_gcm.py
Test mã hóa/giải mã AES-256-GCM với nhiều dạng tin nhắn
khác nhau, bao gồm tiếng Việt có dấu (quan trọng vì ứng dụng chat tiếng Việt).
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
 
 
TEST_MESSAGES = [
    "Hello, this is a test message.",
    "Xin chào! Đây là tin nhắn thử nghiệm có dấu tiếng Việt: ăn uống, nghỉ ngơi.",
    "😀 Emoji test 🚀 và ký tự đặc biệt !@#$%^&*()",
    "",  # chuỗi rỗng - edge case
    "A" * 5000,  # tin nhắn rất dài - edge case
]
 
 
def main():
    print("=" * 60)
    print("NGÀY 4 - TEST MÃ HÓA/GIẢI MÃ AES-256-GCM")
    print("=" * 60)
 
    print("\n[1] Sinh khóa AES-256 phiên (session key)...")
    key = generate_aes_key()
    print(f"    Khóa (hex): {key.hex()}")
    print(f"    Độ dài khóa: {len(key)} byte = {len(key) * 8} bit")
 
    print("\n[2] Test mã hóa/giải mã với nhiều loại tin nhắn khác nhau:\n")
    for i, msg in enumerate(TEST_MESSAGES, start=1):
        display_msg = (msg[:50] + "...") if len(msg) > 50 else (msg if msg else "(chuỗi rỗng)")
        print(f"  Case {i}: \"{display_msg}\" (độ dài gốc: {len(msg)} ký tự)")
 
        enc = aes_encrypt(key, msg)
        print(f"      Nonce  : {enc['nonce'].hex()}")
        print(f"      Tag    : {enc['tag'].hex()}")
        print(f"      Cipher : {enc['ciphertext'].hex()[:40]}{'...' if len(enc['ciphertext'].hex()) > 40 else ''}")
 
        dec = aes_decrypt(key, enc)
        status = "OK - khớp 100%" if dec == msg else "LỖI - KHÔNG KHỚP"
        print(f"      Giải mã: {status}\n")
        assert dec == msg, f"Case {i} thất bại!"
 
    print("[3] Kiểm tra: mỗi lần mã hóa cùng 1 tin nhắn có tạo nonce khác nhau không?")
    msg = "Tin nhắn giống nhau"
    enc1 = aes_encrypt(key, msg)
    enc2 = aes_encrypt(key, msg)
    nonce_khac_nhau = enc1["nonce"] != enc2["nonce"]
    cipher_khac_nhau = enc1["ciphertext"] != enc2["ciphertext"]
    print(f"    Nonce lần 1 : {enc1['nonce'].hex()}")
    print(f"    Nonce lần 2 : {enc2['nonce'].hex()}")
    print(f"    -> Nonce khác nhau: {nonce_khac_nhau} (BẮT BUỘC phải khác nhau để đảm bảo an toàn)")
    print(f"    -> Ciphertext khác nhau dù cùng plaintext: {cipher_khac_nhau}")
    assert nonce_khac_nhau and cipher_khac_nhau
 
    print("\nKẾT QUẢ NGÀY 4: THÀNH CÔNG - Tất cả test case đều đúng")
    print("=" * 60)
 
 
if __name__ == "__main__":
    main()