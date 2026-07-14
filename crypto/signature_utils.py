"""
 
CHỨC NĂNG: Ký số (digital signature) và xác thực chữ ký bằng RSA-PSS + SHA-256.
 
TẠI SAO CẦN THÊM CHỮ KÝ SỐ (đã nêu là "hướng phát triển" trong báo cáo tuần 1)?
AES-GCM (tuần 1) đã đảm bảo:
  - Confidentiality (bí mật): người ngoài không đọc được nội dung
  - Integrity (toàn vẹn): phát hiện được nếu dữ liệu bị sửa trên đường truyền
 
NHƯNG AES-GCM KHÔNG đảm bảo được "Non-repudiation" (không thể chối bỏ):
  Vì AES là mã hóa ĐỐI XỨNG - cả 2 bên (người gửi và người nhận) đều nắm giữ
  CÙNG một session key. Do đó, về mặt lý thuyết mật mã, người NHẬN cũng có đủ
  khả năng tự tạo ra một bản mã "hợp lệ" y hệt như người gửi. Tag của AES-GCM
  chỉ chứng minh dữ liệu "không bị ai sửa", chứ không chứng minh được CHÍNH XÁC
  ai là người đã tạo ra dữ liệu gốc.
 
Chữ ký số RSA giải quyết vấn đề này: chỉ người giữ PRIVATE KEY (chỉ người gửi có)
mới tạo được chữ ký hợp lệ; bất kỳ ai có PUBLIC KEY (ai cũng có) đều xác thực được
chữ ký đó, nhưng không thể tự tạo ra chữ ký giả. Nhờ vậy, chữ ký số chứng minh được
CHÍNH XÁC danh tính người gửi, không chỉ riêng tính toàn vẹn dữ liệu.
 
QUY TRÌNH ÁP DỤNG : "Sign-then-Encrypt" đơn giản hóa —
  Người gửi: (1) ký lên nội dung gốc bằng private key -> (2) mã hóa AES cả nội
             dung lẫn chữ ký -> gửi đi.
  Người nhận: (1) giải mã AES -> (2) xác thực chữ ký bằng public key của người gửi.
 
"""
 
from Crypto.Signature import pss
from Crypto.Hash import SHA256
 
 
def sign_message(private_key, message: str) -> bytes:
    """Ký lên một chuỗi văn bản bằng RSA private key. Trả về chữ ký dạng bytes."""
    h = SHA256.new(message.encode("utf-8"))
    signature = pss.new(private_key).sign(h)
    return signature
 
 
def verify_signature(public_key, message: str, signature: bytes) -> bool:
    """Xác thực chữ ký bằng RSA public key của người được cho là đã gửi tin nhắn.
    Trả về True nếu chữ ký hợp lệ VÀ nội dung không bị thay đổi kể từ lúc ký;
    trả về False trong mọi trường hợp còn lại (không raise exception, để dễ
    dùng trong câu lệnh if của tầng UI)."""
    h = SHA256.new(message.encode("utf-8"))
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
 