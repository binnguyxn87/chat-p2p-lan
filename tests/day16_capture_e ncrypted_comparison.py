"""
Việc cần làm: Lặp lại bài test Ngày 15 nhưng lần này tin nhắn được mã hóa
hybrid (RSA trao khóa + AES-GCM mã hóa nội dung) trước khi gửi qua socket TCP thật.
Bắt gói tin và chứng minh: (1) nội dung KHÔNG đọc được, (2) một số metadata của
gói tin (loại tin nhắn, người gửi, thời gian) VẪN hiển thị dạng plaintext vì đây
là phần "header" của giao thức, chưa được mã hóa - một điểm cần nêu trung thực
trong phần hạn chế của báo cáo.
"""

import sys
import os
import socket
import subprocess
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import aes_encrypt
from crypto.signature_utils import sign_message
from crypto.protocol import (
    build_pubkey_message, build_key_exchange_message, build_chat_message,
    extract_encrypted_session_key, serialize_message, parse_message,
    safe_decrypt_chat_message, MSG_TYPE_PUBKEY, MSG_TYPE_KEY_EXCHANGE, MSG_TYPE_CHAT,
)
from session.session_manager import SessionManager
from Crypto.PublicKey import RSA

HOST = "127.0.0.1"
PORT = 51236
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "security_test", "pcaps")
PCAP_FILE = os.path.join(PCAP_DIR, "02_da_ma_hoa_hybrid.pcap")
TIN_NHAN_THAT = "Chuyen khoan 5 trieu dong cho tai khoan 0123456789 luc 15h chieu nay"


def chay_ben_server(ready_event, ket_qua, loi):
    try:
        my_private, my_public = generate_rsa_keypair()
        manager = SessionManager()
        session = manager.get_or_create("peerA")

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        ready_event.set()

        conn, _ = srv.accept()
        f = conn.makefile("r")

        conn.sendall((serialize_message(build_pubkey_message("peerB", my_public.export_key())) + "\n").encode())
        msg = parse_message(f.readline())
        client_pub = RSA.import_key(msg["public_key_pem"])
        session.set_peer_public_key(client_pub)

        msg = parse_message(f.readline())
        encrypted_key = extract_encrypted_session_key(msg)
        session.receive_encrypted_session_key(my_private, encrypted_key)

        msg = parse_message(f.readline())
        plaintext = safe_decrypt_chat_message(session.session_key, msg)
        ket_qua["server_nhan_duoc"] = plaintext

        conn.close()
        srv.close()
    except Exception as e:
        loi["server"] = repr(e)


def chay_ben_client(ready_event, ket_qua, loi):
    try:
        ready_event.wait(timeout=5)
        my_private, my_public = generate_rsa_keypair()
        manager = SessionManager()
        session = manager.get_or_create("peerB")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        f = sock.makefile("r")

        msg = parse_message(f.readline())
        server_pub = RSA.import_key(msg["public_key_pem"])
        session.set_peer_public_key(server_pub)

        sock.sendall((serialize_message(build_pubkey_message("peerA", my_public.export_key())) + "\n").encode())

        encrypted_key = session.generate_and_encrypt_session_key()
        sock.sendall((serialize_message(build_key_exchange_message("peerA", encrypted_key)) + "\n").encode())
        session.confirm_established()

        enc = aes_encrypt(session.session_key, TIN_NHAN_THAT)
        signature = sign_message(my_private, TIN_NHAN_THAT)
        sock.sendall((serialize_message(build_chat_message("peerA", enc, signature=signature)) + "\n").encode())
        ket_qua["client_da_gui"] = TIN_NHAN_THAT

        time.sleep(0.3)
        sock.close()
    except Exception as e:
        loi["client"] = repr(e)


def main():
    print("=" * 60)
    print("NGÀY 16 - CAPTURE TRAFFIC ĐÃ MÃ HÓA (SO SÁNH VỚI BASELINE NGÀY 15)")
    print("=" * 60)

    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\nTin nhắn thật (giống hệt Ngày 15 để so sánh công bằng): \"{TIN_NHAN_THAT}\"")
    print("Lần này: mã hóa AES-GCM + ký số RSA trước khi gửi qua socket TCP thật.")

    print(f"\n[1] Bắt đầu tcpdump, capture cổng {PORT}...")
    tcpdump_proc = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-w", PCAP_FILE, f"port {PORT}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)

    print("[2] Chạy luồng bắt tay + gửi tin nhắn đã mã hóa qua socket TCP...")
    ready_event = threading.Event()
    ket_qua, loi = {}, {}
    t_server = threading.Thread(target=chay_ben_server, args=(ready_event, ket_qua, loi))
    t_client = threading.Thread(target=chay_ben_client, args=(ready_event, ket_qua, loi))
    t_server.start(); t_client.start()
    t_server.join(timeout=10); t_client.join(timeout=10)
    time.sleep(1)

    if loi:
        print("CÓ LỖI:", loi)
        sys.exit(1)
    assert ket_qua["client_da_gui"] == ket_qua["server_nhan_duoc"]
    print(f"    -> Xác nhận: giải mã ở đầu nhận khớp 100% với bản gốc.")

    print("\n[3] Dừng tcpdump, lưu file capture...")
    tcpdump_proc.terminate()
    tcpdump_proc.wait(timeout=5)
    print(f"    -> Đã lưu: {PCAP_FILE}")

    print("\n[4] Phân tích bằng tshark...")
    result = subprocess.run(
        ["tshark", "-r", PCAP_FILE, "-Y", "tcp.len > 0", "-x"],
        capture_output=True, text=True,
    )

    tu_dau = TIN_NHAN_THAT.split()[0]  # "Chuyen"
    tim_thay_plaintext = tu_dau in result.stdout
    tim_thay_header_json = '"type"' in result.stdout or "type" in result.stdout

    print("-" * 60)
    print("[Trích đúng gói tin chat_message - phần quan trọng nhất để đưa vào báo cáo]")
    chat_packet_result = subprocess.run(
        ["tshark", "-r", PCAP_FILE, "-Y", 'tcp contains "chat_message"', "-x"],
        capture_output=True, text=True,
    )
    print(chat_packet_result.stdout[:1800])
    print("-" * 60)
    print("=> Quan sát: phần đầu gói tin (type/sender/timestamp) vẫn là JSON đọc")
    print("   được, nhưng phần 'ciphertext' trong payload là chuỗi byte NGẪU NHIÊN,")
    print("   không mang ý nghĩa - đây chính là bằng chứng trực quan tốt nhất để")
    print("   chụp màn hình đưa vào báo cáo (so sánh cạnh ảnh chụp Ngày 15).")

    print(f"\n[KẾT QUẢ SO SÁNH VỚI BASELINE NGÀY 15]")
    print(f"  Tìm thấy nội dung gốc \"{tu_dau}...\" dạng plaintext: {tim_thay_plaintext}")
    if not tim_thay_plaintext:
        print("  => DỮ LIỆU NỘI DUNG TIN NHẮN ĐÃ ĐƯỢC BẢO VỆ - không đọc được")
        print("     ngay cả khi bắt được toàn bộ gói tin trên đường truyền.")
    else:
        print("  => [CẢNH BÁO] Phát hiện rò rỉ plaintext - cần kiểm tra lại code!")

    print(f"\n  Metadata (type/sender/timestamp) có hiển thị plaintext: {tim_thay_header_json}")
    print("  => ĐÂY LÀ ĐIỂM CẦN NÊU TRUNG THỰC TRONG BÁO CÁO: hệ thống hiện tại")
    print("     chỉ mã hóa PHẦN NỘI DUNG (payload), phần header giao thức (ai gửi,")
    print("     loại gói tin, thời gian) vẫn ở dạng plaintext để bên nhận còn biết")
    print("     cách xử lý gói tin. Đây là điều bình thường ngay cả trong các giao")
    print("     thức thực tế (VD: TLS cũng để lộ một số metadata), nhưng nên được")
    print("     ghi rõ trong phần 'Đánh giá bảo mật' thay vì bỏ qua.")

    assert not tim_thay_plaintext, "LỖI NGHIÊM TRỌNG: nội dung tin nhắn bị rò rỉ plaintext!"

    print(f"\n=> File '{os.path.basename(PCAP_FILE)}' có thể mở trực tiếp bằng Wireshark")
    print("   trên máy bạn, đặt cạnh file Ngày 15 để so sánh trực quan trong báo cáo.")
    print("\nKẾT QUẢ NGÀY 16: THÀNH CÔNG")
    print("=" * 60)


if __name__ == "__main__":
    main()
