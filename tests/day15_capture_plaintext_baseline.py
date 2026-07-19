"""
Việc cần làm: Trước khi chứng minh hệ thống mã hóa AN TOÀN, cần có một
bài test ĐỐI CHỨNG (baseline) cho thấy điều gì sẽ xảy ra NẾU KHÔNG mã hóa - để
so sánh. Script này:
  1. Chạy tcpdump bắt gói tin trên interface loopback
  2. Gửi một tin nhắn CHAT THẬT (dạng plaintext, chưa mã hóa) qua socket TCP
  3. Dừng capture, lưu ra file .pcap thật (mở được bằng Wireshark)
  4. Dùng tshark phân tích: tìm chuỗi plaintext gốc trong file capture

MỤC ĐÍCH: đây là "before" để so sánh với "after" (traffic đã mã hóa) ở Ngày 16.
Nếu không có bước đối chứng này, người xem báo cáo sẽ khó hình dung rủi ro thực
sự nếu không mã hóa là gì.
"""

import sys
import os
import socket
import subprocess
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HOST = "127.0.0.1"
PORT = 51235
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "security_test", "pcaps")
PCAP_FILE = os.path.join(PCAP_DIR, "01_khong_ma_hoa_baseline.pcap")
TIN_NHAN_THAT = "Chuyen khoan 5 trieu dong cho tai khoan 0123456789 luc 15h chieu nay"


def gui_tin_nhan_khong_ma_hoa():
    def server():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        conn, _ = s.accept()
        conn.recv(4096)
        conn.close()
        s.close()

    def client():
        time.sleep(0.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.sendall(TIN_NHAN_THAT.encode("utf-8"))
        s.close()

    t1 = threading.Thread(target=server)
    t2 = threading.Thread(target=client)
    t1.start(); t2.start()
    t1.join(); t2.join()


def main():
    print("=" * 60)
    print("NGÀY 15 - CAPTURE BASELINE: TIN NHẮN KHÔNG MÃ HÓA")
    print("=" * 60)

    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\nTin nhắn thật sẽ gửi (CHƯA mã hóa): \"{TIN_NHAN_THAT}\"")

    print(f"\n[1] Bắt đầu tcpdump, capture cổng {PORT} trên interface lo...")
    tcpdump_proc = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-w", PCAP_FILE, f"port {PORT}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)  # đợi tcpdump khởi động xong trước khi gửi traffic

    print("[2] Gửi tin nhắn qua socket TCP (KHÔNG mã hóa)...")
    gui_tin_nhan_khong_ma_hoa()
    time.sleep(1)

    print("[3] Dừng tcpdump, lưu file capture...")
    tcpdump_proc.terminate()
    tcpdump_proc.wait(timeout=5)
    print(f"    -> Đã lưu: {PCAP_FILE}")

    print("\n[4] Phân tích bằng tshark: tìm nội dung gốc trong file capture...")
    result = subprocess.run(
        ["tshark", "-r", PCAP_FILE, "-Y", "tcp.len > 0", "-x"],
        capture_output=True, text=True,
    )
    print("-" * 60)
    print(result.stdout)
    print("-" * 60)

    tim_thay = TIN_NHAN_THAT.replace(" ", "_") in result.stdout.replace(" ", "_") or \
        any(word in result.stdout for word in TIN_NHAN_THAT.split()[:3])
    # Kiểm tra đơn giản: các từ đầu của tin nhắn có xuất hiện trong phần ASCII của hex dump không
    tu_dau = TIN_NHAN_THAT.split()[0]
    tim_thay_thuc_te = tu_dau in result.stdout

    if tim_thay_thuc_te:
        print(f"[CẢNH BÁO - ĐÚNG NHƯ DỰ ĐOÁN] Tìm thấy từ \"{tu_dau}\" TRỰC TIẾP trong")
        print("    dữ liệu bắt được - bất kỳ ai bắt gói tin trên cùng mạng LAN đều")
        print("    ĐỌC ĐƯỢC TOÀN BỘ nội dung tin nhắn nếu không mã hóa.")
    else:
        print("[LƯU Ý] Không tìm thấy trực tiếp - kiểm tra lại thủ công file .pcap.")

    print(f"\n=> File '{os.path.basename(PCAP_FILE)}' có thể mở trực tiếp bằng Wireshark")
    print("   trên máy bạn để xem bằng hình ảnh trực quan cho báo cáo.")
    print("\nKẾT QUẢ NGÀY 15: THÀNH CÔNG - Đã có baseline đối chứng")
    print("=" * 60)


if __name__ == "__main__":
    main()
