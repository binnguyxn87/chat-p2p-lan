# [BẢN NHÁP] Bổ sung báo cáo Tuần 2 — Module Bảo mật (Thành viên B)

> Nối tiếp file `draft_bao_cao_module_bao_mat.md` của Tuần 1. Phần này bổ sung mục 7-10.

---

## 7. Nâng cấp giao thức truyền tin (Tuần 2)

### 7.1. Từ mô phỏng nội bộ đến giao thức mạng thực sự

Ở Tuần 1, mã hóa lai được kiểm chứng bằng cách gọi hàm trực tiếp trong cùng một tiến trình
Python. Tuần 2 giải quyết vấn đề thực tế: dữ liệu `bytes` (khóa, ciphertext...) cần được
đóng gói thành văn bản (JSON) để truyền qua socket. Nhóm xây dựng module `protocol.py` thực
hiện việc này bằng mã hóa Base64, với 3 loại gói tin chuẩn hóa:

| Loại gói tin | Mục đích |
|---|---|
| `pubkey_exchange` | Trao đổi RSA public key khi 2 peer mới kết nối |
| `key_exchange` | Gửi session key AES đã được mã hóa bằng RSA |
| `chat_message` | Nội dung tin nhắn đã mã hóa AES-GCM, có thể kèm chữ ký số |

### 7.2. Máy trạng thái quản lý phiên (Session State Machine)

Do ứng dụng P2P cần hỗ trợ nhiều peer kết nối đồng thời, nhóm thiết kế lớp `PeerSession`
theo dõi trạng thái bắt tay của từng peer độc lập, quản lý tập trung bởi `SessionManager`:

```
NEW → PUBKEY_RECEIVED → (chủ động: KEY_SENT →) ESTABLISHED
```

**

**Kết quả kiểm thử:** đã kiểm chứng `SessionManager` quản lý đồng thời 3 peer với 3 session key
độc lập, không có hiện tượng trộn lẫn khóa giữa các phiên.

## 8. Tích hợp qua kết nối mạng thật

Nhóm xây dựng bài test độc lập mô phỏng 2 tiến trình (`server` và `client`) giao tiếp qua
socket TCP thật tại `127.0.0.1`, thực hiện đầy đủ chu trình: trao đổi public key → trao đổi
session key qua RSA → gửi 1 tin nhắn mã hóa AES-GCM → xác nhận nội dung nhận được khớp
100% với nội dung gửi đi.

**Ý nghĩa:** đây là bằng chứng cho thấy module Bảo mật đã sẵn sàng để tích hợp với module
Networking thực tế (Tuần 3) — chỉ cần thay lớp gửi/nhận socket thô bằng module hoàn chỉnh
của A, toàn bộ logic mã hóa/bắt tay giữ nguyên không đổi nhờ thiết kế tách module rõ ràng.

## 9. Bổ sung Chữ ký số (Digital Signature)

### 9.1. Động lực

AES-GCM (Tuần 1) đảm bảo tính bí mật và toàn vẹn, nhưng do là mã hóa đối xứng, không thể
chứng minh được *chính xác ai* là người tạo ra tin nhắn gốc (cả hai bên đều nắm chung một
khóa). Nhóm bổ sung chữ ký số RSA (chuẩn RSA-PSS + SHA-256) để đạt thêm thuộc tính **xác thực
danh tính người gửi (authenticity)** và **không thể chối bỏ (non-repudiation)**.

### 9.2. Cơ chế "Sign-then-Encrypt"

Người gửi ký lên nội dung gốc bằng private key của mình trước, sau đó mã hóa AES-GCM cả nội
dung và chữ ký cùng lúc. Người nhận giải mã trước, rồi xác thực chữ ký bằng public key của
người gửi.

**Kết quả kiểm thử (3 kịch bản):**

| Kịch bản | Kết quả |
|---|---|
| Xác thực chữ ký hợp lệ với đúng public key người gửi | `True` — hợp lệ |
| Nội dung bị sửa sau khi ký (thử đổi 1 số trong tin nhắn) | `False` — phát hiện sai lệch |
| Dùng public key của người khác để xác thực (giả mạo danh tính) | `False` — phát hiện mạo danh |

## 10. Xác thực thủ công qua Fingerprint & Xử lý kết nối lại

### 10.1. Fingerprint (Safety Number)

Để giảm thiểu rủi ro tấn công Man-in-the-Middle ở lần bắt tay đầu tiên (hạn chế đã nêu ở
báo cáo Tuần 1), nhóm bổ sung cơ chế sinh "fingerprint" — mã băm SHA-256 rút gọn, dễ đọc,
của public key mỗi peer — tương tự "Safety Number" của Signal. Người dùng có thể đối chiếu
fingerprint qua một kênh liên lạc khác để xác nhận không bị nghe lén.

*(Lưu ý khi thuyết trình: đây là biện pháp giảm thiểu thủ công, không phải hệ thống PKI/CA
tự động hoàn chỉnh — nên trình bày rõ giới hạn này thay vì nhận vơ là giải pháp toàn diện.)*

### 10.2. Xử lý khi peer ngắt kết nối / kết nối lại

Đã kiểm chứng: khi một `PeerSession` bị hủy (`invalidate()`, gọi khi phát hiện mất kết nối),
session key cũ bị xóa hoàn toàn khỏi bộ nhớ. Khi peer kết nối lại, hệ thống bắt buộc thực
hiện lại toàn bộ quy trình bắt tay và sinh ra session key HOÀN TOÀN MỚI — đã xác nhận session
key giữa 2 lần kết nối luôn khác nhau, giới hạn thiệt hại nếu một session key nào đó từng bị
lộ trong quá khứ.

## 11. Kiểm thử toàn diện & độ tin cậy

Nhóm xây dựng bộ 8 tình huống lỗi mô phỏng các sự cố thực tế có thể xảy ra khi vận hành
(gói tin JSON hỏng, thiếu trường dữ liệu, base64 lỗi, sai session key, chữ ký giả mạo, gọi
sai thứ tự hàm, nhiều peer hoạt động đồng thời). **Kết quả: 8/8 tình huống được xử lý đúng**,
toàn bộ lỗi được gói gọn thành một loại ngoại lệ thống nhất (`CryptoProtocolError`) để tầng
giao diện (C) dễ dàng bắt và hiển thị thông báo phù hợp mà không làm crash ứng dụng.

## 12. Hạn chế còn lại và hướng phát triển Tuần 3

- Fingerprint hiện mới dừng ở mức hiển thị — chưa có cảnh báo tự động nếu fingerprint của
  một peer quen thuộc bỗng thay đổi giữa 2 lần kết nối (có thể bổ sung nếu còn thời gian).
- Chưa kiểm thử bảo mật bằng công cụ bắt gói tin thực tế (Wireshark) — dự kiến thực hiện
  Tuần 3 để có bằng chứng trực quan mạnh nhất cho báo cáo cuối kỳ.
- Digital signature hiện là tùy chọn (optional field) — cần bàn với nhóm xem có bắt buộc
  ký mọi tin nhắn hay chỉ áp dụng cho một số loại thao tác nhạy cảm, để cân bằng giữa bảo
  mật và hiệu năng (ký + xác thực chữ ký cũng tốn thời gian xử lý RSA).