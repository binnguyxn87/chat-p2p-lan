"""
Kiểm tra máy trạng thái PeerSession hoạt động đúng thứ tự,
và SessionManager quản lý được nhiều peer cùng lúc (mô phỏng tình huống P2P thật
khi một máy chat với 2-3 máy khác đồng thời).
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair
from session.session_manager import SessionManager, SessionState
 
 
def test_handshake_hai_ben():
    print("=" * 60)
    print("PHẦN A - MÔ PHỎNG BẮT TAY GIỮA 2 PEER (dùng PeerSession)")
    print("=" * 60)
 
    # Mỗi "máy" có khóa RSA + SessionManager riêng, y hệt thực tế
    a_private, a_public = generate_rsa_keypair()
    b_private, b_public = generate_rsa_keypair()
 
    manager_A = SessionManager()
    manager_B = SessionManager()
 
    session_A_ve_B = manager_A.get_or_create("peerB")  # góc nhìn của A về B
    session_B_ve_A = manager_B.get_or_create("peerA")  # góc nhìn của B về A
 
    print(f"\nTrạng thái ban đầu:")
    print(f"  A nhìn B: {session_A_ve_B}")
    print(f"  B nhìn A: {session_B_ve_A}")
    assert session_A_ve_B.state == SessionState.NEW
    assert session_B_ve_A.state == SessionState.NEW
 
    print("\n[Bước 1] A gửi public key cho B, B gửi public key cho A (mô phỏng)")
    session_A_ve_B.mark_pubkey_sent()
    session_B_ve_A.mark_pubkey_sent()
    session_A_ve_B.set_peer_public_key(b_public)   # A nhận được public key của B
    session_B_ve_A.set_peer_public_key(a_public)   # B nhận được public key của A
    print(f"  A nhìn B: {session_A_ve_B}")
    print(f"  B nhìn A: {session_B_ve_A}")
    assert session_A_ve_B.state == SessionState.PUBKEY_RECEIVED
    assert session_B_ve_A.state == SessionState.PUBKEY_RECEIVED
 
    print("\n[Bước 2] A đóng vai trò CHỦ ĐỘNG: sinh + mã hóa + gửi session key")
    encrypted_key = session_A_ve_B.generate_and_encrypt_session_key()
    session_A_ve_B.confirm_established()
    print(f"  A nhìn B: {session_A_ve_B}")
    assert session_A_ve_B.state == SessionState.ESTABLISHED
    assert session_A_ve_B.is_initiator is True
 
    print("\n[Bước 3] B nhận gói tin key_exchange, giải mã bằng private key của mình")
    session_B_ve_A.receive_encrypted_session_key(b_private, encrypted_key)
    print(f"  B nhìn A: {session_B_ve_A}")
    assert session_B_ve_A.state == SessionState.ESTABLISHED
 
    print("\n[Bước 4] Kiểm tra 2 bên có cùng session key không (yếu tố sống còn)")
    khop = session_A_ve_B.session_key == session_B_ve_A.session_key
    print(f"  Session key khớp nhau: {khop}")
    assert khop, "LỖI NGHIÊM TRỌNG: 2 bên không cùng session key!"
 
    print("\n=> Máy trạng thái hoạt động đúng thứ tự NEW -> PUBKEY_RECEIVED -> ESTABLISHED")
 
 
def test_quan_ly_nhieu_peer():
    print("\n" + "=" * 60)
    print("PHẦN B - SESSIONMANAGER QUẢN LÝ NHIỀU PEER ĐỒNG THỜI")
    print("=" * 60)
 
    my_private, my_public = generate_rsa_keypair()
    manager = SessionManager()
 
    danh_sach_peer = ["peerA", "peerC", "peerD"]
    print(f"\nGiả lập máy hiện tại kết nối đồng thời với: {danh_sach_peer}")
 
    for peer_id in danh_sach_peer:
        s = manager.get_or_create(peer_id)
        _, peer_pub_key = generate_rsa_keypair()  # giả lập mỗi peer có khóa riêng
        s.mark_pubkey_sent()
        s.set_peer_public_key(peer_pub_key)
        s.generate_and_encrypt_session_key()
        s.confirm_established()
 
    print(f"Tổng số session đang quản lý: {len(manager)}")
    print(f"Danh sách peer đã ESTABLISHED: {manager.list_established_peers()}")
    assert len(manager) == 3
    assert set(manager.list_established_peers()) == set(danh_sach_peer)
    print("-> Quản lý đồng thời 3 peer, mỗi peer có session key riêng biệt. OK.")
 
    # Kiểm tra mỗi peer có session key khác nhau (không dùng chung 1 khóa)
    keys = [manager.get_or_create(p).session_key for p in danh_sach_peer]
    assert len(set(keys)) == 3, "LỖI: 2 peer đang dùng chung 1 session key!"
    print("-> Xác nhận mỗi peer có session key AES ĐỘC LẬP, không trùng nhau. OK.")
 
 
if __name__ == "__main__":
    test_handshake_hai_ben()
    test_quan_ly_nhieu_peer()
    print("\n" + "=" * 60)
    print("KẾT QUẢ NGÀY 9: THÀNH CÔNG")
    print("=" * 60)