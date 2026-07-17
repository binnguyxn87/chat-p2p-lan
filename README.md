# Chat P2P LAN

Ứng dụng chat ngang hàng (Peer-to-Peer) trong mạng LAN, sử dụng mã hóa lai **RSA-2048 + AES-256-GCM**, kèm chữ ký số RSA đảm bảo toàn vẹn và xác thực tin nhắn.

**Đồ án môn:** [Tên môn học]
**Nhóm:** 3 thành viên — Thời hạn: 3 tuần

## Thành viên & phân công

| Thành viên | Module | Thư mục |
|---|---|---|
| Nguyễn Trường Nhân | Networking / Lõi P2P | `network/` |
| Tống Quang Hưng | Bảo mật (RSA + AES + chữ ký số) | `crypto/`, `session/` |
| Lương Việt Hoàn Thiện | Giao diện người dùng | `ui/` |

## Kiến trúc tổng quan

- **Khám phá peer:** UDP broadcast tự động tìm các máy trong cùng mạng LAN
- **Kết nối:** TCP, hỗ trợ đa kết nối đồng thời (nhiều peer cùng lúc)
- **Bắt tay bảo mật:** trao đổi RSA public key → sinh khóa AES phiên → mã hóa khóa AES bằng RSA → gửi qua kênh TCP
- **Mã hóa tin nhắn:** AES-256-GCM (vừa mã hóa vừa đảm bảo toàn vẹn), kèm chữ ký số RSA xác thực người gửi

## Cấu trúc thư mục
network/    - Module Networking: socket TCP, UDP discovery, đa kết nối, xử lý lỗi mạng
crypto/     - Module Bảo mật: RSA, AES-GCM, chữ ký số, fingerprint public key
session/    - Quản lý phiên bắt tay (state machine) và giao thức đóng gói dữ liệu mã hóa
ui/         - Giao diện người dùng
docs/       - Tài liệu API, báo cáo tiến độ

## Cách chạy thử (module Networking + Bảo mật)

```bash
cd network
python run_peer.py <ten_cua_ban> <cong_lang_nghe>
```
Ví dụ: mở 2 terminal, chạy `python run_peer.py PeerA 5000` và `python run_peer.py PeerB 5001` — 2 tiến trình sẽ tự động tìm và kết nối với nhau, tự bắt tay trao khóa mã hóa, sau đó có thể chat bằng lệnh `broadcast <nội dung>`.

## Trạng thái hiện tại

- [x] Kết nối TCP, đa kết nối, khám phá peer tự động (UDP)
- [x] Xử lý lỗi mạng, ngắt kết nối an toàn
- [x] Mã hóa lai RSA + AES, chữ ký số — đã tích hợp và kiểm thử qua mạng thật
- [ ] Giao diện người dùng (đang phát triển)
- [ ] Kiểm thử bảo mật bằng Wireshark
- [ ] Báo cáo tổng kết
