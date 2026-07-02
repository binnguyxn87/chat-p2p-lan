# API Module Networking (dành cho C tích hợp UI, và B cắm mã hóa)

## Khởi tạo 1 peer
​```python
from peer import Peer
from discovery import Discovery

peer = Peer(my_name="TenBan", listen_port=5000)

# Bắt đầu lắng nghe kết nối đến (chạy trong thread riêng)
import threading
threading.Thread(target=peer.start_listening, daemon=True).start()

# Bắt đầu tự động khám phá peer trong LAN
def khi_tim_thay_peer(ten_peer, ip, port):
    peer.connect_to(ip, port)

discovery = Discovery(my_name="TenBan", my_listen_port=5000, on_peer_found=khi_tim_thay_peer)
discovery.start()
​```

## Các hàm C có thể gọi

| Hàm | Mô tả | Ví dụ |
|---|---|---|
| `peer.connect_to(ip, port)` | Kết nối thủ công tới 1 peer | `peer.connect_to("192.168.1.10", 5000)` |
| `peer.send_message(addr, text)` | Gửi tin nhắn riêng tới 1 peer, trả về True/False | `peer.send_message(("192.168.1.10", 5000), "Xin chào")` |
| `peer.broadcast(text)` | Gửi tin nhắn tới TẤT CẢ peer đang kết nối | `peer.broadcast("Chào mọi người")` |
| `peer.list_peers()` | Trả về danh sách địa chỉ peer đang kết nối | `peer.list_peers()` → `[('192.168.1.10', 5000), ...]` |
| `peer.shutdown()` | Đóng toàn bộ kết nối trước khi thoát app | Gọi khi người dùng đóng cửa sổ UI |

## Để C hiển thị tin nhắn đến trên UI

Hiện tại `peer.py` in tin nhắn ra console (`print`). C cần thay việc này bằng cách gán 1 callback tương tự cách B gán encrypt_hook — **(việc này A sẽ bổ sung nếu C yêu cầu)**.
Tạm thời, C có thể tự đọc trực tiếp `peer.connections` để lấy danh sách peer online hiển thị lên UI.

## Để B cắm mã hóa vào

​```python
peer.encrypt_hook = ham_ma_hoa_cua_B   # nhận (text, addr) → trả về ciphertext (string)
peer.decrypt_hook = ham_giai_ma_cua_B  # nhận (ciphertext, addr) → trả về text gốc (string)
​```

Nếu không gán, hệ thống tự động chạy ở chế độ plaintext (không mã hóa) — dùng để test độc lập module Networking.

## Định dạng gói tin JSON (dùng nội bộ, ít khi cần đụng tới)
​```json
{
  "type": "MESSAGE",
  "sender": "ten_nguoi_gui",
  "payload": "noi_dung (hoac ciphertext neu da ma hoa)",
  "timestamp": "2026-07-02T10:00:00"
}