"""
Ngày phát triển: Ngày 4-5 (Tuần 1)
 
CHỨC NĂNG:
- Sinh khóa AES-256 ngẫu nhiên (dùng làm khóa phiên - session key)
- Mã hóa/giải mã nội dung tin nhắn bằng AES-256-GCM
 
TẠI SAO CHỌN GCM THAY VÌ CBC:
- GCM (Galois/Counter Mode) là chế độ AEAD (Authenticated Encryption with
  Associated Data): vừa mã hóa (confidentiality) VỪA tạo ra "tag" xác thực
  toàn vẹn dữ liệu (integrity/authenticity) trong MỘT bước duy nhất.
- CBC chỉ đảm bảo bí mật, muốn có toàn vẹn phải ghép thêm HMAC riêng
  (phức tạp hơn, dễ làm sai nếu cài đặt thủ công - lỗi kinh điển "padding oracle").
- GCM không cần padding thủ công (khác CBC phải tự thêm PKCS7 padding).
- Phù hợp cho ứng dụng chat: cần đảm bảo tin nhắn không bị bên thứ ba
  chỉnh sửa trên đường truyền trong mạng LAN.
"""
 
from Crypto.Cipher import AES
import os
 
AES_KEY_SIZE = 32  # byte = 256 bit
 
 
def generate_aes_key() -> bytes:
    """Sinh khóa AES-256 ngẫu nhiên bằng CSPRNG (os.urandom), dùng làm session key."""
    return os.urandom(AES_KEY_SIZE)
 
 
def aes_encrypt(key: bytes, plaintext: str) -> dict:
    """
    Mã hóa một chuỗi văn bản bằng AES-256-GCM.
 
    Returns:
        dict gồm 3 phần cần gửi đi cho bên nhận:
        - nonce: số dùng 1 lần (bắt buộc phải khác nhau mỗi lần mã hóa với cùng 1 key)
        - ciphertext: dữ liệu đã mã hóa
        - tag: mã xác thực dùng để kiểm tra toàn vẹn khi giải mã
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return {
        "nonce": cipher.nonce,
        "ciphertext": ciphertext,
        "tag": tag,
    }
 
 
def aes_decrypt(key: bytes, enc_dict: dict) -> str:
    """
    Giải mã + xác thực toàn vẹn cùng lúc.
 
    Raises:
        ValueError: nếu ciphertext hoặc tag bị sửa đổi (dữ liệu không toàn vẹn)
                    -> đây chính là cơ chế chống tấn công can thiệp dữ liệu (tampering).
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=enc_dict["nonce"])
    plaintext = cipher.decrypt_and_verify(enc_dict["ciphertext"], enc_dict["tag"])
    return plaintext.decode("utf-8")

