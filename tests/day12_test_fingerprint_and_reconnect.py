"""
  (A) Kiểm tra fingerprint sinh đúng, khác nhau giữa các khóa khác nhau
  (B) Kiểm tra khi peer ngắt kết nối và kết nối lại, hệ thống KHÔNG được tái sử
      dụng session key cũ mà phải bắt tay lại từ đầu (an toàn hơn)
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair
from crypto.fingerprint_utils import get_public_key_fingerprint, so_sanh_fingerprint
from session.session_manager import SessionManager, SessionState
 
 
def test_fingerprint():
    print("=" * 60)
    print("PHẦN A - FINGERPRINT CỦA PUBLIC KEY")
    print("=" * 60)
 
    _, public_key_1 = generate_rsa_keypair()
    _, public_key_2 = generate_rsa_keypair()
 
    fp1 = get_public_key_fingerprint(public_key_1.export_key())
    fp2 = get_public_key_fingerprint(public_key_2.export_key())
    fp1_lai = get_public_key_fingerprint(public_key_1.export_key())  # tính lại lần nữa
 
    print(f"\nFingerprint khóa 1       : {fp1}")
    print(f"Fingerprint khóa 2       : {fp2}")
    print(f"Fingerprint khóa 1 (lại) : {fp1_lai}")
 
    assert not so_sanh_fingerprint(fp1, fp2), "LỖI: 2 khóa khác nhau lại ra cùng fingerprint!"
    assert so_sanh_fingerprint(fp1, fp1_lai), "LỖI: cùng 1 khóa lại ra fingerprint khác nhau!"
    print("\n-> 2 khóa khác nhau cho fingerprint khác nhau. OK.")
    print("-> Cùng 1 khóa luôn cho ra fingerprint giống hệt (ổn định). OK.")
    print("\n=> ỨNG DỤNG THỰC TẾ: hiển thị fingerprint này lên UI khi 2 người chat lần")
    print("   đầu, để họ có thể đọc cho nhau nghe qua điện thoại xác nhận đúng người.")
 
 
def test_xu_ly_reconnect():
    print("\n" + "=" * 60)
    print("PHẦN B - XỬ LÝ KHI PEER NGẮT KẾT NỐI VÀ KẾT NỐI LẠI")
    print("=" * 60)
 
    a_private, a_public = generate_rsa_keypair()
    b_private, b_public = generate_rsa_keypair()
 
    manager = SessionManager()
    session = manager.get_or_create("peerA")
 
    print("\n[Lần kết nối 1] Bắt tay bình thường")
    session.mark_pubkey_sent()
    session.set_peer_public_key(a_public)
    encrypted_key = session.generate_and_encrypt_session_key()
    session.confirm_established()
    session_key_lan_1 = session.session_key
    print(f"    Trạng thái: {session}")
    print(f"    Session key lần 1 (hex, rút gọn): {session_key_lan_1.hex()[:20]}...")
    assert session.is_ready()
 
    print("\n[Sự kiện] Peer A đột ngột mất kết nối (rớt mạng / đóng ứng dụng)")
    session.invalidate()
    print(f"    Trạng thái sau khi invalidate(): {session}")
    assert session.state == SessionState.NEW
    assert session.session_key is None
    assert not session.is_ready()
    print("    -> Session đã bị hủy, session key cũ đã xóa khỏi bộ nhớ. OK.")
 
    print("\n[Lần kết nối 2] Peer A kết nối lại - PHẢI bắt tay lại từ đầu")
    session.mark_pubkey_sent()
    session.set_peer_public_key(a_public)
    session.generate_and_encrypt_session_key()
    session.confirm_established()
    session_key_lan_2 = session.session_key
    print(f"    Trạng thái: {session}")
    print(f"    Session key lần 2 (hex, rút gọn): {session_key_lan_2.hex()[:20]}...")
 
    assert session_key_lan_1 != session_key_lan_2, "LỖI BẢO MẬT: tái sử dụng session key cũ!"
    print("\n-> Session key lần 2 KHÁC HOÀN TOÀN session key lần 1. OK.")
    print("=> Ý NGHĨA BẢO MẬT: nếu kẻ tấn công từng lấy được session key cũ")
    print("   (VD: qua một lỗ hổng tạm thời đã được vá), việc bắt buộc tạo")
    print("   session key mới mỗi lần kết nối giúp giới hạn thiệt hại chỉ trong")
    print("   phạm vi 1 phiên, không ảnh hưởng các phiên chat sau này.")
 
 
if __name__ == "__main__":
    test_fingerprint()
    test_xu_ly_reconnect()
    print("\n" + "=" * 60)
    print("KẾT QUẢ NGÀY 12: THÀNH CÔNG")
    print("=" * 60)