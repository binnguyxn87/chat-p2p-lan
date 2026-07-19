# Kiến trúc hệ thống — Chat P2P LAN

Tài liệu này tóm tắt kiến trúc kỹ thuật, dùng làm nội dung cho báo cáo và phần thuyết trình.

## 1. Tổng quan kiến trúc

Hệ thống theo mô hình **Peer-to-Peer thuần** (không có server trung tâm). Mỗi máy chạy ứng dụng vừa đóng vai trò server (lắng nghe kết nối đến) vừa đóng vai trò client (chủ động kết nối ra), gọi chung là "peer".

```
┌─────────────┐          UDP Broadcast           ┌─────────────┐
│   Peer A    │ ───── (khám phá lẫn nhau) ─────▶ │   Peer B    │
│             │ ◀───────────────────────────────  │             │
└──────┬──────┘                                   └──────┬──────┘
       │              TCP Socket (kết nối trực tiếp)      │
       └───────────────────────────────────────────────────┘
                            │
                 Bắt tay RSA → trao khóa AES
                            │
                 Chat: AES-256-GCM + chữ ký RSA
```

## 2. Luồng khám phá & kết nối

1. Mỗi peer khi khởi động sẽ **UDP broadcast** định kỳ (mỗi 3 giây) ra toàn mạng LAN, thông báo tên và cổng TCP đang lắng nghe.
2. Khi 1 peer nhận được thông báo từ peer khác, áp dụng **quy tắc tie-breaking**: chỉ bên có cổng lắng nghe nhỏ hơn mới chủ động kết nối TCP tới bên kia — tránh tình trạng cả 2 bên cùng lúc kết nối lẫn nhau, tạo ra 2 kết nối trùng lặp.
3. Sau khi kết nối TCP thành công, quá trình bắt tay bảo mật bắt đầu.

## 3. Luồng bắt tay bảo mật (mã hóa lai)

1. Cả 2 bên sinh cặp khóa **RSA-2048** khi khởi động, gửi **public key** cho nhau ngay khi kết nối (gói tin loại `PUBKEY`).
2. Chỉ bên **chủ động kết nối** (initiator) mới sinh khóa **AES-256** ngẫu nhiên (khóa phiên/session key).
3. Bên chủ động **mã hóa khóa AES bằng RSA public key** của đối phương (RSA-OAEP padding), gửi đi (gói tin loại `KEY_EXCHANGE`).
4. Bên nhận dùng **RSA private key** của mình giải mã, thu được khóa AES phiên dùng chung.
5. Từ thời điểm này, 2 bên có chung 1 khóa AES bí mật — không truyền trực tiếp qua mạng dưới dạng lộ liễu, chỉ truyền dạng đã mã hóa RSA.

## 4. Luồng gửi/nhận tin nhắn

Khi bắt tay hoàn tất, mỗi tin nhắn gửi đi trải qua:

1. **Mã hóa AES-256-GCM** nội dung bằng khóa phiên — tạo ra `ciphertext` + `tag` xác thực toàn vẹn + `nonce` ngẫu nhiên
2. **Ký số RSA-PSS (SHA-256)** trên nội dung gốc bằng private key người gửi — tạo chữ ký chứng minh danh tính
3. Đóng gói `{nonce, ciphertext, tag, signature}` thành JSON, gửi qua socket TCP

Khi nhận:
1. Giải mã AES-GCM — nếu `tag` không khớp (dữ liệu bị sửa/hỏng giữa đường) → tự động báo lỗi, từ chối xử lý
2. Xác thực chữ ký số bằng public key đã trao đổi trước đó — nếu sai → cảnh báo "chữ ký không hợp lệ, có thể bị giả mạo"
3. Hiển thị nội dung gốc lên giao diện

## 5. Bằng chứng trực quan (phục vụ demo/bảo vệ)

Ứng dụng tích hợp sẵn tính năng **"Xem dữ liệu mạng"** (Menu Tuỳ chọn), cho phép quan sát trực tiếp:
- Dữ liệu **thực sự truyền qua socket** (dạng ciphertext, hoàn toàn không đọc được)
- So sánh với nội dung **đã giải mã hiển thị trong khung chat**

Đây là bằng chứng tự thân của hệ thống, có thể bổ sung thêm bằng công cụ Wireshark (bắt gói tin ở tầng hệ điều hành) để có thêm minh chứng khách quan độc lập.

## 6. Xử lý lỗi & độ tin cậy

- Kết nối bị ngắt đột ngột (rút mạng, tắt tiến trình) → tự động dọn dẹp, không crash, các peer còn lại cập nhật danh sách ngay
- Kết nối tới địa chỉ không tồn tại → báo lỗi rõ ràng, có timeout tránh treo ứng dụng
- Nếu tag AES hoặc chữ ký số không hợp lệ → không hiển thị nhầm nội dung giả mạo, có cảnh báo riêng

## 7. Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python 3 |
| Giao tiếp mạng | `socket` (TCP + UDP), `threading` |
| Mã hóa | `pycryptodome` (RSA-OAEP, AES-GCM, RSA-PSS/SHA-256) |
| Giao diện | `tkinter` (có sẵn trong Python) |
