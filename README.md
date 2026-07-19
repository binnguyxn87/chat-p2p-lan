# Chat P2P LAN

Ứng dụng chat ngang hàng (Peer-to-Peer) trong mạng LAN, mã hóa lai **RSA-2048 + AES-256-GCM**, kèm chữ ký số RSA đảm bảo toàn vẹn và xác thực người gửi.

## Thành viên & phân công

| Thành viên | Module | Thư mục |
|---|---|---|
| Nguyễn Trường Nhân | Networking / Lõi P2P, tích hợp hệ thống, Giao diện | `network/`, `ui/` |
| Tống Quang Hưng | Bảo mật (RSA + AES + chữ ký số) | `crypto/`, `session/` |
| Lương Việt Hoàn Thiện | Thiết kế giao diện ban đầu, góp ý UX | `ui/` (bản thiết kế tham khảo) |

## Cấu trúc thư mục

```
main.py             - Điểm khởi chạy ứng dụng
requirements.txt    - Thư viện cần cài (pycryptodome)

network/             - Module Networking
  peer.py             - Socket TCP, đa kết nối, xử lý lỗi mạng
  discovery.py         - UDP broadcast, tự động khám phá peer trong LAN
  protocol.py           - Giao thức đóng gói tin nhắn (JSON)
  crypto_bridge.py     - Cầu nối bắt tay + điều phối mã hóa/giải mã

crypto/               - Module Bảo mật
  rsa_utils.py          - Sinh khóa & mã hóa/giải mã RSA-2048 (OAEP)
  aes_utils.py           - Mã hóa/giải mã nội dung AES-256-GCM
  signature_utils.py    - Ký & xác thực chữ ký số (RSA-PSS + SHA-256)

session/              - Thiết kế quản lý phiên bắt tay (state machine) do
                         thành viên Bảo mật xây dựng; dùng làm tài liệu tham
                         khảo thiết kế trong báo cáo (bản chạy chính thức
                         dùng logic tương đương được tích hợp trực tiếp
                         trong network/crypto_bridge.py để đảm bảo tiến độ).

ui/                   - Giao diện người dùng
  gui.py                 - Tkinter: đăng nhập, khung chat, menu, log gói tin

docs/                  - Tài liệu, báo cáo tiến độ, tài liệu kiến trúc
```

## Cách chạy

```bash
pip install -r requirements.txt
python main.py
```

Mở nhiều cửa sổ (nhiều terminal) với cổng khác nhau để giả lập nhiều người dùng trên 1 máy, hoặc chạy trên nhiều máy thật trong cùng mạng LAN — ứng dụng tự động tìm và kết nối.

Chi tiết đầy đủ xem tại [`HUONG_DAN.md`](HUONG_DAN.md).

## Tính năng chính

- Tự động khám phá peer trong LAN (UDP broadcast), không cần server trung tâm
- Hỗ trợ nhiều peer kết nối đồng thời
- Bắt tay mã hóa tự động: trao đổi RSA public key → sinh khóa AES phiên → mã hóa khóa qua RSA
- Mọi tin nhắn được mã hóa AES-256-GCM và ký số RSA trước khi gửi
- Giao diện hiển thị đúng tên người dùng (không lộ địa chỉ IP thô ra giao diện chính)
- Tính năng "Xem dữ liệu mạng" (menu Tuỳ chọn) — cho phép quan sát trực tiếp dữ liệu ciphertext thực tế truyền qua socket, dùng để minh chứng tính bảo mật khi báo cáo/bảo vệ đồ án
- Xử lý ngắt kết nối và lỗi mạng an toàn, không làm crash ứng dụng

## Đã kiểm thử

- Bắt tay RSA + trao khóa AES qua socket TCP thật
- Mã hóa/giải mã AES-256-GCM + xác thực chữ ký số qua nhiều lượt gửi
- Đa kết nối đồng thời (đã test 4 tiến trình cùng lúc)
- Giao diện: đăng nhập, chat broadcast, chat riêng, resize cửa sổ, hiển thị trạng thái mã hóa từng peer
- Nhật ký gói tin xác nhận không rò rỉ nội dung gốc (plaintext) ra dữ liệu truyền mạng
