# Hướng dẫn chạy ứng dụng Chat P2P LAN

## 1. Cài thư viện cần thiết (chỉ cần làm 1 lần)

```bash
pip install -r requirements.txt
```

(Tkinter dùng để làm giao diện đã có sẵn trong Python, không cần cài thêm. Nếu máy Windows báo thiếu tkinter, cài lại Python từ python.org và nhớ tick đủ các thành phần mặc định.)

## 2. Chạy ứng dụng

```bash
python main.py
```

Một cửa sổ đăng nhập hiện ra:
- Nhập **tên hiển thị**
- Nhập **cổng lắng nghe** (mỗi máy/mỗi tiến trình phải dùng cổng khác nhau, ví dụ 5000, 5001, 5002...)
- Bấm **"Vào phòng chat"**

## 3. Test với nhiều người/nhiều máy

- **Trên 1 máy (giả lập nhiều người):** mở nhiều cửa sổ dòng lệnh (terminal), mỗi cửa sổ chạy `python main.py` với cổng khác nhau.
- **Trên nhiều máy thật trong cùng mạng LAN/Wifi:** mỗi máy chạy `python main.py` bình thường (không cần chỉnh sửa IP), ứng dụng sẽ **tự động tìm và kết nối** với các máy khác trong cùng mạng LAN.

## 4. Sử dụng

- Danh sách bên trái hiển thị các peer đang kết nối. Biểu tượng 🔒 nghĩa là đã bắt tay mã hóa xong, sẵn sàng chat an toàn; ⏳ nghĩa là đang bắt tay.
- **Không chọn peer nào** (bấm "Bỏ chọn") → gõ tin nhắn sẽ **gửi cho tất cả** (broadcast).
- **Chọn 1 peer cụ thể** trong danh sách → tin nhắn chỉ gửi riêng cho người đó.
- Mọi tin nhắn đều tự động được **mã hóa AES-256-GCM**, khóa AES được trao đổi an toàn qua **RSA-2048**, kèm **chữ ký số RSA** xác thực người gửi — người dùng không cần thao tác gì thêm, ứng dụng tự xử lý ở tầng dưới.

## 5. Kiến trúc kỹ thuật (tóm tắt cho báo cáo)

| Thành phần | File | Vai trò |
|---|---|---|
| Lõi mạng P2P | `network/peer.py` | Socket TCP, đa kết nối, xử lý lỗi/ngắt kết nối |
| Khám phá peer | `network/discovery.py` | UDP broadcast, tự tìm peer trong LAN |
| Giao thức tin nhắn | `network/protocol.py` | Đóng gói JSON (type/sender/payload/timestamp) |
| Cầu nối bảo mật | `network/crypto_bridge.py` | Điều phối bắt tay + mã hóa/giải mã |
| RSA | `crypto/rsa_utils.py` | Sinh khóa 2048-bit, mã hóa/giải mã khóa phiên (OAEP) |
| AES | `crypto/aes_utils.py` | Mã hóa/giải mã nội dung tin nhắn (AES-256-GCM) |
| Chữ ký số | `crypto/signature_utils.py` | Ký & xác thực người gửi (RSA-PSS + SHA-256) |
| Giao diện | `ui/gui.py` | Tkinter: màn hình đăng nhập + cửa sổ chat |

## 6. Đã kiểm thử

- ✅ Bắt tay RSA + trao khóa AES qua mạng thật (socket TCP)
- ✅ Mã hóa/giải mã AES-256-GCM + xác thực chữ ký số đúng qua nhiều lượt gửi
- ✅ Tự động khám phá & kết nối nhiều peer (đã test với 4 tiến trình đồng thời)
- ✅ Giao diện Tkinter hoạt động đầy đủ: đăng nhập, chat broadcast, chat riêng, hiển thị trạng thái mã hóa từng peer
- ✅ Xử lý ngắt kết nối, lỗi mạng không làm crash ứng dụng
