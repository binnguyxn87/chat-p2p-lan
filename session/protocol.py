"""
CHỨC NĂNG:
Tuần 1 các hàm mã hóa chỉ làm việc với `bytes` (nonce, ciphertext, tag, khóa RSA đã
mã hóa...). Nhưng khi truyền qua socket mạng, dữ liệu cần được đóng gói thành dạng
văn bản (JSON) để cả nhóm (đặc biệt là A - Networking) có một định dạng thống nhất
khi gửi/nhận. Module này là "lớp chuyển đổi" giữa dữ liệu mã hóa (bytes) và gói tin
mạng (JSON string).
 
TẠI SAO CẦN BASE64:
JSON chỉ hỗ trợ text (Unicode), không hỗ trợ trực tiếp dữ liệu nhị phân (bytes).
Base64 chuyển bytes thành một chuỗi ký tự an toàn để nhúng vào JSON.
 
CÁC LOẠI GÓI TIN (message type) trong giao thức:
- pubkey_exchange : trao đổi RSA public key giữa 2 peer khi mới kết nối
- key_exchange    : gửi session key AES đã được mã hóa bằng RSA
- chat_message    : nội dung tin nhắn đã mã hóa bằng AES-GCM (có thể kèm chữ ký số)
"""
 
import json
import base64
import time
 
 
MSG_TYPE_PUBKEY = "pubkey_exchange"
MSG_TYPE_KEY_EXCHANGE = "key_exchange"
MSG_TYPE_CHAT = "chat_message"
MSG_TYPE_ERROR = "error"
 
 
class CryptoProtocolError(Exception):
    """Lỗi chuẩn hóa cho mọi sự cố liên quan tới giao thức/mã hóa, để module UI (C)
    chỉ cần bắt MỘT loại exception thay vì phải biết hết các lỗi con bên trong
    (KeyError, ValueError, binascii.Error...)."""
    pass
 
 
# ---------- Chuyển đổi bytes <-> chuỗi (để nhúng vào JSON) ----------
 
def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
 
 
def decode_bytes(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
 
 
# ---------- Xây dựng từng loại gói tin ----------
 
def build_pubkey_message(sender_id: str, public_key_pem: bytes) -> dict:
    """public_key_pem: kết quả của public_key.export_key() (dạng PEM, đã là text-safe)."""
    return {
        "type": MSG_TYPE_PUBKEY,
        "sender": sender_id,
        "timestamp": time.time(),
        "public_key_pem": public_key_pem.decode("utf-8"),
    }
 
 
def build_key_exchange_message(sender_id: str, encrypted_session_key: bytes) -> dict:
    return {
        "type": MSG_TYPE_KEY_EXCHANGE,
        "sender": sender_id,
        "timestamp": time.time(),
        "encrypted_session_key": encode_bytes(encrypted_session_key),
    }
 
 
def build_chat_message(sender_id: str, enc_dict: dict, signature: bytes = None) -> dict:
    """enc_dict: kết quả trả về từ aes_encrypt() ở tuần 1: {nonce, ciphertext, tag}.
    signature: chữ ký số tùy chọn (thêm ở Ngày 11) để xác thực người gửi."""
    msg = {
        "type": MSG_TYPE_CHAT,
        "sender": sender_id,
        "timestamp": time.time(),
        "payload": {
            "nonce": encode_bytes(enc_dict["nonce"]),
            "ciphertext": encode_bytes(enc_dict["ciphertext"]),
            "tag": encode_bytes(enc_dict["tag"]),
        },
    }
    if signature is not None:
        msg["signature"] = encode_bytes(signature)
    return msg
 
 
# ---------- Trích xuất dữ liệu từ gói tin đã nhận ----------
 
def extract_encrypted_session_key(msg: dict) -> bytes:
    return decode_bytes(msg["encrypted_session_key"])
 
 
def extract_enc_dict(msg: dict) -> dict:
    p = msg["payload"]
    return {
        "nonce": decode_bytes(p["nonce"]),
        "ciphertext": decode_bytes(p["ciphertext"]),
        "tag": decode_bytes(p["tag"]),
    }
 
 
def extract_signature(msg: dict):
    if msg.get("signature") is not None:
        return decode_bytes(msg["signature"])
    return None
 
 
# ---------- Serialize / Parse (dùng khi gửi/nhận qua socket) ----------
 
def serialize_message(msg: dict) -> str:
    """Chuyển dict -> chuỗi JSON. A sẽ gọi hàm này trước khi conn.sendall()."""
    return json.dumps(msg)
 
 
def parse_message(raw: str) -> dict:
    """Chuyển chuỗi nhận được từ socket -> dict. Raise CryptoProtocolError nếu
    dữ liệu không phải JSON hợp lệ (VD: gói tin bị lỗi/cắt cụt trên đường truyền)."""
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError as e:
        raise CryptoProtocolError(f"Gói tin không phải JSON hợp lệ: {e}")
 
 
def safe_decrypt_chat_message(session_key: bytes, msg: dict):
    """Hàm tiện ích tổng hợp: trích xuất + giải mã 1 gói tin chat, gộp mọi lỗi có
    thể xảy ra (thiếu field, base64 hỏng, giải mã thất bại) thành CryptoProtocolError
    duy nhất - để C (UI) chỉ cần try/except 1 loại lỗi.
    """
    from crypto.aes_utils import aes_decrypt  # import trễ để tránh vòng lặp import
 
    try:
        enc_dict = extract_enc_dict(msg)
    except KeyError as e:
        raise CryptoProtocolError(f"Gói tin chat thiếu trường dữ liệu: {e}")
    except (ValueError, Exception) as e:  # base64 lỗi -> binascii.Error (con của ValueError)
        raise CryptoProtocolError(f"Dữ liệu base64 trong gói tin bị hỏng: {e}")
 
    try:
        return aes_decrypt(session_key, enc_dict)
    except ValueError as e:
        raise CryptoProtocolError(f"Giải mã thất bại (sai khóa hoặc dữ liệu bị can thiệp): {e}")