"""
Module AES - mã hóa/giải mã nội dung tin nhắn bằng AES-256-GCM.
GCM vừa mã hóa vừa tạo "tag" xác thực toàn vẹn (chống chỉnh sửa dữ liệu giữa đường).
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_aes_key() -> bytes:
    """Sinh khóa AES-256 ngẫu nhiên (32 byte) - dùng làm khóa phiên (session key)."""
    return get_random_bytes(32)


def aes_encrypt(key: bytes, plaintext: str) -> dict:
    """Mã hóa 1 chuỗi văn bản bằng AES-256-GCM. Trả về dict gồm nonce, ciphertext, tag (đều là bytes)."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return {
        "nonce": cipher.nonce,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def aes_decrypt(key: bytes, enc: dict) -> str:
    """Giải mã dữ liệu đã mã hóa bằng AES-256-GCM. Ném lỗi nếu tag không khớp (dữ liệu bị sửa/hỏng)."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=enc["nonce"])
    plaintext = cipher.decrypt_and_verify(enc["ciphertext"], enc["tag"])
    return plaintext.decode('utf-8')
