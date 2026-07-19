"""
Module chữ ký số - dùng RSA-PSS + SHA-256 để ký và xác thực tin nhắn.
Đảm bảo tin nhắn thực sự đến từ đúng người gửi (chống giả mạo danh tính),
bổ sung cho AES-GCM (vốn chỉ đảm bảo toàn vẹn, chưa xác thực danh tính).
"""
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def sign_message(private_key, message: str) -> bytes:
    """Ký 1 chuỗi văn bản bằng RSA private key. Trả về chữ ký (bytes)."""
    h = SHA256.new(message.encode('utf-8'))
    signature = pss.new(private_key).sign(h)
    return signature


def verify_signature(public_key, message: str, signature: bytes) -> bool:
    """Kiểm tra chữ ký có hợp lệ không. Trả về True/False, không ném lỗi."""
    h = SHA256.new(message.encode('utf-8'))
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
