"""
CHỨC NĂNG:
Sinh "vân tay" (fingerprint) ngắn, dễ đọc của một RSA public key.
 
Toàn bộ hệ thống bắt tay (RSA + AES) đảm bảo an toàn NẾU public key nhận được
lúc bắt đầu thực sự thuộc về đúng người mình muốn chat. Nhưng trong LẦN KẾT NỐI
ĐẦU TIÊN, làm sao biết chắc public key nhận qua mạng LAN không bị kẻ tấn công
đứng giữa (Man-in-the-Middle) tráo đổi?
 
GIẢI PHÁP ĐƠN GIẢN TRONG PHẠM VI:
Hiển thị "fingerprint" (mã băm SHA-256 của public key, rút gọn thành chuỗi dễ đọc)
lên giao diện. Người dùng có thể so sánh fingerprint này với người kia qua một
kênh khác (nói miệng, gọi điện, nhắn Zalo...) để xác nhận thủ công. Đây chính là
nguyên lý "Safety Number" mà Signal/WhatsApp dùng.
 
LƯU Ý: đây là biện pháp GIẢM THIỂU rủi ro, không phải giải pháp xác
thực tự động hoàn chỉnh, nên trình bày rõ ràng giới hạn này khi thuyết trình.
"""
 
import hashlib
 
 
def get_public_key_fingerprint(public_key_pem: bytes) -> str:
    """Trả về chuỗi fingerprint dạng dễ đọc, ví dụ: '3f2a 9c1d 88ab ... '."""
    digest = hashlib.sha256(public_key_pem).hexdigest()
    groups = [digest[i:i + 4] for i in range(0, len(digest), 4)]
    return " ".join(groups)
 
 
def so_sanh_fingerprint(fp1: str, fp2: str) -> bool:
    """So khớp 2 fingerprint (dùng khi hiển thị cảnh báo tự động nếu 2 lần kết nối
    liên tiếp với cùng 1 peer_id lại cho ra fingerprint KHÁC NHAU - dấu hiệu đáng ngờ
    của tấn công MITM hoặc peer đã đổi khóa)."""
    return fp1.strip() == fp2.strip()