"""
Module RSA - sinh cặp khóa 2048-bit, mã hóa/giải mã dùng padding OAEP.
Dùng để trao đổi khóa AES phiên một cách an toàn (mã hóa lai).
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keypair():
    """Sinh cặp khóa RSA 2048-bit. Trả về (private_key, public_key)."""
    key = RSA.generate(2048)
    return key, key.publickey()


def export_public_key(public_key):
    """Chuyển public key thành chuỗi PEM (string) để gửi qua mạng."""
    return public_key.export_key().decode('utf-8')


def import_public_key(pem_str):
    """Chuyển chuỗi PEM nhận được từ mạng thành đối tượng public key."""
    return RSA.import_key(pem_str)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Mã hóa dữ liệu (thường là khóa AES phiên, tối đa ~190 byte với khóa 2048-bit) bằng RSA-OAEP."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """Giải mã dữ liệu đã mã hóa bằng RSA-OAEP."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)
