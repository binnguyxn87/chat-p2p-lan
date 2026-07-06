"""
day5_test_integrity_and_performance.py
  (A) Chứng minh AES-GCM phát hiện được dữ liệu bị giả mạo/sửa đổi (tính toàn vẹn)
  (B) So sánh tốc độ RSA vs AES để có số liệu thực nghiệm cho báo cáo,
      củng cố lý do dùng AES cho phần mã hóa nội dung tin nhắn.
 
"""
 
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
 
 
def test_tamper_detection():
    print("=" * 60)
    print("PHẦN A - KIỂM TRA PHÁT HIỆN GIẢ MẠO DỮ LIỆU (TÍNH TOÀN VẸN)")
    print("=" * 60)
 
    key = generate_aes_key()
    message = "Chuyển khoản 1.000.000 VND cho Nguyễn Văn A"
    enc = aes_encrypt(key, message)
    print(f"\nTin nhắn gốc: \"{message}\"")
    print(f"Đã mã hóa OK.")
 
    # --- Kịch bản 1: Kẻ tấn công sửa 1 byte trong ciphertext ---
    print("\n[Kịch bản 1] Kẻ tấn công (Man-in-the-middle) sửa 1 byte trong ciphertext...")
    tampered = dict(enc)
    tampered_ct = bytearray(tampered["ciphertext"])
    tampered_ct[0] ^= 0xFF
    tampered["ciphertext"] = bytes(tampered_ct)
    try:
        aes_decrypt(key, tampered)
        print("    -> [NGUY HIỂM] Giải mã thành công dù dữ liệu đã bị sửa! (không mong đợi)")
    except ValueError as e:
        print(f"    -> Từ chối giải mã. Lỗi: '{e}'")
        print("    -> ĐÚNG NHƯ KỲ VỌNG: hệ thống phát hiện dữ liệu bị can thiệp.")
 
    # --- Kịch bản 2: Kẻ tấn công sửa tag xác thực ---
    print("\n[Kịch bản 2] Kẻ tấn công sửa tag xác thực...")
    tampered2 = dict(enc)
    tampered_tag = bytearray(tampered2["tag"])
    tampered_tag[0] ^= 0xFF
    tampered2["tag"] = bytes(tampered_tag)
    try:
        aes_decrypt(key, tampered2)
        print("    -> [NGUY HIỂM] Giải mã thành công dù tag đã bị sửa! (không mong đợi)")
    except ValueError as e:
        print(f"    -> Từ chối giải mã. Lỗi: '{e}'")
        print("    -> ĐÚNG NHƯ KỲ VỌNG.")
 
    # --- Kịch bản 3: Giải mã đúng, không có can thiệp ---
    print("\n[Kịch bản 3] Trường hợp bình thường, không có can thiệp...")
    dec = aes_decrypt(key, enc)
    print(f"    -> Giải mã thành công: \"{dec}\"")
    assert dec == message
 
    print("\n=> KẾT LUẬN CHO BÁO CÁO: AES-GCM đảm bảo thuộc tính TOÀN VẸN")
    print("   (integrity) và XÁC THỰC (authenticity), không chỉ riêng BÍ MẬT")
    print("   (confidentiality). Bất kỳ thay đổi nào trên đường truyền dù chỉ")
    print("   1 bit đều khiến quá trình giải mã thất bại ngay lập tức.")
 
 
def test_performance_comparison():
    print("\n" + "=" * 60)
    print("PHẦN B - SO SÁNH HIỆU NĂNG RSA vs AES")
    print("=" * 60)
 
    private_key, public_key = generate_rsa_keypair()
    aes_key = generate_aes_key()
 
    # So sánh trên cùng 1 khối dữ liệu nhỏ (32 byte) mà cả 2 đều xử lý được
    data_32 = os.urandom(32)
 
    N = 100
    print(f"\nMã hóa {N} lần với khối dữ liệu 32 byte, đo tổng thời gian:")
 
    t0 = time.perf_counter()
    for _ in range(N):
        rsa_encrypt(public_key, data_32)
    t_rsa = time.perf_counter() - t0
 
    t0 = time.perf_counter()
    for _ in range(N):
        aes_encrypt(aes_key, data_32.hex())
    t_aes = time.perf_counter() - t0
 
    print(f"    RSA-2048 : {t_rsa*1000:.2f} ms tổng ({t_rsa/N*1000:.4f} ms/lần)")
    print(f"    AES-256  : {t_aes*1000:.2f} ms tổng ({t_aes/N*1000:.4f} ms/lần)")
    print(f"    -> AES nhanh hơn RSA khoảng {t_rsa/t_aes:.1f} lần trên cùng khối lượng dữ liệu nhỏ.")
 
    # Thử với dữ liệu lớn hơn nhiều (1KB) - RSA sẽ không làm được, AES vẫn ổn
    print(f"\nThử mã hóa một tin nhắn lớn hơn (2000 byte, ví dụ file nhỏ / tin nhắn dài):")
    big_message = "x" * 2000
    try:
        rsa_encrypt(public_key, big_message.encode())
        print("    RSA: [không mong đợi] mã hóa thành công")
    except ValueError:
        print("    RSA: THẤT BẠI (vượt giới hạn ~214 byte) -> không khả thi")
 
    t0 = time.perf_counter()
    enc_big = aes_encrypt(aes_key, big_message)
    t_aes_big = time.perf_counter() - t0
    dec_big = aes_decrypt(aes_key, enc_big)
    assert dec_big == big_message
    print(f"    AES: THÀNH CÔNG trong {t_aes_big*1000:.4f} ms, không giới hạn độ dài")
 
    print("\n=> KẾT LUẬN CHO BÁO CÁO: Số liệu thực nghiệm trên củng cố lý do kiến")
    print("   trúc HYBRID là lựa chọn đúng đắn - RSA an toàn cho trao đổi khóa")
    print("   (dữ liệu nhỏ, ít lần thực hiện) nhưng chậm và giới hạn kích thước;")
    print("   AES nhanh và không giới hạn độ dài, phù hợp mã hóa nội dung chat")
    print("   liên tục với tần suất cao.")
 
 
if __name__ == "__main__":
    test_tamper_detection()
    test_performance_comparison()
    print("\n" + "=" * 60)
    print("KẾT QUẢ NGÀY 5: THÀNH CÔNG")
    print("=" * 60)
 
