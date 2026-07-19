"""
Việc cần làm: Tuần 2 để ngỏ câu hỏi "có nên BẮT BUỘC ký số mọi tin nhắn
hay chỉ áp dụng tùy chọn?". Ngày này đo hiệu năng THỰC TẾ của toàn bộ pipeline
(mã hóa AES + ký RSA + đóng gói JSON) để đưa ra quyết định DỰA TRÊN SỐ LIỆU,
không phải cảm tính.
"""

import sys
import os
import time
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
from crypto.signature_utils import sign_message, verify_signature
from crypto.protocol import build_chat_message, serialize_message, parse_message, extract_signature, extract_enc_dict

SO_LAN_DO = 200
TIN_NHAN_MAU = "Chào bạn, tin nhắn chat bình thường có độ dài trung bình khoảng cỡ này."


def pipeline_khong_ky(private_key, session_key, message):
    enc = aes_encrypt(session_key, message)
    msg = build_chat_message("peerA", enc)
    raw = serialize_message(msg)
    parsed = parse_message(raw)
    enc_dict = extract_enc_dict(parsed)
    aes_decrypt(session_key, enc_dict)


def pipeline_co_ky(private_key, public_key, session_key, message):
    signature = sign_message(private_key, message)
    enc = aes_encrypt(session_key, message)
    msg = build_chat_message("peerA", enc, signature=signature)
    raw = serialize_message(msg)
    parsed = parse_message(raw)
    enc_dict = extract_enc_dict(parsed)
    plaintext = aes_decrypt(session_key, enc_dict)
    sig = extract_signature(parsed)
    verify_signature(public_key, plaintext, sig)


def do_thoi_gian(ham, *args, so_lan=SO_LAN_DO):
    thoi_gian_moi_lan = []
    for _ in range(so_lan):
        t0 = time.perf_counter()
        ham(*args)
        thoi_gian_moi_lan.append((time.perf_counter() - t0) * 1000)  # ms
    return thoi_gian_moi_lan


def main():
    print("=" * 60)
    print("NGÀY 18 - BENCHMARK PIPELINE: QUYẾT ĐỊNH CHÍNH SÁCH KÝ SỐ")
    print("=" * 60)

    private_key, public_key = generate_rsa_keypair()
    session_key = generate_aes_key()

    print(f"\nĐo {SO_LAN_DO} lần cho mỗi pipeline, tin nhắn mẫu dài {len(TIN_NHAN_MAU)} ký tự...")

    print("\n[1] Pipeline KHÔNG ký số (chỉ mã hóa AES-GCM + đóng gói JSON)")
    t_khong_ky = do_thoi_gian(pipeline_khong_ky, private_key, session_key, TIN_NHAN_MAU)
    print(f"    Trung bình : {statistics.mean(t_khong_ky):.4f} ms")
    print(f"    Trung vị   : {statistics.median(t_khong_ky):.4f} ms")

    print("\n[2] Pipeline CÓ ký số (ký RSA-PSS + mã hóa AES-GCM + đóng gói + xác thực chữ ký)")
    t_co_ky = do_thoi_gian(pipeline_co_ky, private_key, public_key, session_key, TIN_NHAN_MAU)
    print(f"    Trung bình : {statistics.mean(t_co_ky):.4f} ms")
    print(f"    Trung vị   : {statistics.median(t_co_ky):.4f} ms")

    chenh_lech = statistics.mean(t_co_ky) - statistics.mean(t_khong_ky)
    ty_le = statistics.mean(t_co_ky) / statistics.mean(t_khong_ky)

    print(f"\n[3] So sánh")
    print(f"    Chênh lệch trung bình : +{chenh_lech:.4f} ms / tin nhắn")
    print(f"    Chậm hơn khoảng       : {ty_le:.2f} lần")

    print(f"\n[4] Đối chiếu với ngưỡng cảm nhận được của con người")
    print("    Đây là ứng dụng CHAT - tốc độ tương tác theo nhịp con người gõ phím,")
    print("    không phải hệ thống machine-to-machine tần suất cực cao. Ngưỡng độ")
    print("    trễ mà con người bắt đầu CẢM NHẬN được thường là > 100 ms.")
    print(f"    Overhead do ký số: {chenh_lech:.4f} ms/tin nhắn")

    if chenh_lech < 100:
        print("    -> Overhead này NHỎ HƠN RẤT NHIỀU so với ngưỡng con người cảm")
        print("       nhận được (dù CHẬM HƠN TƯƠNG ĐỐI ~10 lần so với không ký,")
        print("       xét về số tuyệt đối vẫn hoàn toàn không ảnh hưởng trải nghiệm).")
        khuyen_nghi = "BẮT BUỘC ký số cho MỌI tin nhắn chat"
        ly_do = (f"dù chậm hơn ~{ty_le:.1f} lần về mặt TƯƠNG ĐỐI, số tuyệt đối "
                 f"(+{chenh_lech:.2f} ms) vẫn vô hình với người dùng trong một ứng "
                 f"dụng chat tương tác theo nhịp con người; lợi ích bảo mật "
                 f"(xác thực danh tính + chống chối bỏ) đáng giá hơn nhiều so với "
                 f"chi phí không đáng kể này")
    else:
        print("    -> Overhead này CÓ THỂ nhận thấy được, cần cân nhắc kỹ.")
        khuyen_nghi = "chỉ ký số cho các thao tác NHẠY CẢM (không bắt buộc mọi tin nhắn)"
        ly_do = f"chi phí thêm ({chenh_lech:.4f} ms/tin nhắn) đủ lớn để cân nhắc chọn lọc"

    print(f"\n[KẾT LUẬN - QUYẾT ĐỊNH THIẾT KẾ DỰA TRÊN SỐ LIỆU]")
    print(f"    Khuyến nghị: {khuyen_nghi}")
    print(f"    Lý do: {ly_do}.")

    print("\nKẾT QUẢ NGÀY 18: THÀNH CÔNG - Đã có số liệu thực nghiệm cho quyết định thiết kế")
    print("=" * 60)

    return {
        "trung_binh_khong_ky_ms": statistics.mean(t_khong_ky),
        "trung_binh_co_ky_ms": statistics.mean(t_co_ky),
        "chenh_lech_ms": chenh_lech,
        "khuyen_nghi": khuyen_nghi,
    }


if __name__ == "__main__":
    main()
