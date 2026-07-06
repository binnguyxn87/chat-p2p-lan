"""
 
CHỨC NĂNG:
- Sinh cặp khóa RSA (public/private)
- Lưu và đọc khóa từ file (định dạng PEM)
- Mã hóa/giải mã dữ liệu NGẮN bằng RSA (dùng để mã hóa khóa phiên AES, KHÔNG dùng
  để mã hóa trực tiếp nội dung tin nhắn vì RSA có giới hạn kích thước dữ liệu đầu vào)
 
LÝ DO CHỌN THAM SỐ:
- Key size 2048-bit: mức khuyến nghị tối thiểu hiện nay (NIST), cân bằng giữa
  độ an toàn và tốc độ tính toán (4096-bit an toàn hơn nhưng chậm hơn đáng kể).
- Padding PKCS1_OAEP: chuẩn padding an toàn cho mã hóa RSA, chống lại một số
  dạng tấn công mà padding PKCS1v1.5 (cũ) dễ bị khai thác.
"""
 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
 
RSA_KEY_SIZE = 2048  # bits
 
 
def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE):
    """
    Sinh một cặp khóa RSA mới.
 
    Returns:
        (private_key, public_key): đối tượng khóa RSA của pycryptodome
    """
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key
 
 
def save_key_to_file(key, filepath: str) -> None:
    """Lưu khóa (public hoặc private) ra file định dạng PEM."""
    with open(filepath, "wb") as f:
        f.write(key.export_key())
 
 
def load_key_from_file(filepath: str):
    """Đọc khóa RSA từ file PEM."""
    with open(filepath, "rb") as f:
        return RSA.import_key(f.read())
 
 
def max_encryptable_bytes(key_size: int = RSA_KEY_SIZE, hash_len: int = 20) -> int:
    """
    Tính kích thước dữ liệu tối đa (byte) mà RSA-OAEP có thể mã hóa trực tiếp
    với key_size cho trước. Công thức OAEP: k - 2*hLen - 2 (k = key_size/8 byte).
    Dùng để MINH HỌA cho báo cáo lý do vì sao cần mã hóa lai (hybrid).
    """
    k = key_size // 8
    return k - 2 * hash_len - 2
 
 
def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    Mã hóa dữ liệu bằng public key (PKCS1_OAEP).
 
    LƯU Ý QUAN TRỌNG :
    RSA-OAEP chỉ mã hóa được dữ liệu có kích thước tối đa xấp xỉ
    (key_size/8 - 42) byte. Với khóa 2048-bit, giới hạn là 214 byte.
    Vì vậy RSA KHÔNG dùng để mã hóa trực tiếp nội dung tin nhắn dài,
    mà chỉ dùng để mã hóa khóa AES phiên (32 byte) -> đây chính là bản chất
    của mã hóa lai (hybrid encryption).
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)
 
 
def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """Giải mã dữ liệu đã mã hóa bằng RSA public key tương ứng, dùng private key."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)
