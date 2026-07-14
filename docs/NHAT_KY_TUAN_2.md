# NHẬT KÝ LÀM VIỆC — TUẦN 2
## Thành viên: B (Module Bảo mật — Giao thức mạng, Chữ ký số, Xác thực)


| Ngày | Công việc thực hiện | Kết quả | Minh chứng | Ghi chú / khó khăn gặp phải |
|---|---|---|---|---|
| Ngày 8 | Thiết kế và cài đặt giao thức đóng gói JSON (`protocol.py`) cho 3 loại gói tin: pubkey_exchange, key_exchange, chat_message | Đóng gói/giải gói đúng 100%; phát hiện đúng gói tin JSON hỏng | `crypto/protocol.py`, `tests/day8_test_protocol_serialization.py` | *(VD: cần tìm hiểu vì sao JSON không nhúng trực tiếp được bytes, phải qua base64)* |
| Ngày 9 | Xây dựng máy trạng thái `PeerSession` + `SessionManager` quản lý bắt tay cho nhiều peer đồng thời | Bắt tay đúng thứ tự trạng thái; quản lý 3 peer đồng thời với session key độc lập | `session/session_manager.py`, `tests/day9_test_session_handshake.py` | *(VD: ban đầu nhầm lẫn giữa vai trò "chủ động" và "bị động" trong bắt tay)* |
| Ngày 10 | Viết bài test tích hợp qua socket TCP thật (server + client 2 tiến trình) | Toàn bộ luồng bắt tay + mã hóa hoạt động đúng qua kết nối mạng thật, không chỉ gọi hàm nội bộ | `tests/day10_test_socket_integration.py` | *(VD: cần đồng bộ threading để server sẵn sàng trước khi client kết nối, dùng threading.Event)* |
| Ngày 11 | Cài đặt chữ ký số RSA-PSS (`signature_utils.py`), tích hợp "sign-then-encrypt" vào gói tin chat | Ký/xác thực đúng; phát hiện được nội dung bị sửa và giả mạo danh tính | `crypto/signature_utils.py`, `tests/day11_test_digital_signature.py` | *(VD: tìm hiểu vì sao chọn PSS thay vì PKCS1v1.5 cho chữ ký)* |
| Ngày 12 | Cài đặt fingerprint public key (`fingerprint_utils.py`); xử lý invalidate session khi peer ngắt kết nối | Fingerprint ổn định, phân biệt đúng các khóa khác nhau; session key đổi mới hoàn toàn sau reconnect | `crypto/fingerprint_utils.py`, `tests/day12_test_fingerprint_and_reconnect.py` | *(VD: ...)* |
| Ngày 13 | Viết bộ 8 tình huống kiểm thử lỗi toàn diện (JSON hỏng, base64 lỗi, sai khóa, sai chữ ký, sai thứ tự gọi hàm, đa peer) | 8/8 tình huống xử lý đúng, không crash | `tests/day13_test_comprehensive_edge_cases.py` | *(VD: ...)* |
| Ngày 14 | Cập nhật đặc tả interface v2 cho A/C; viết tiếp báo cáo Tuần 2; họp nhóm review | Bàn giao đầy đủ hàm cho A tích hợp Tuần 3; thống nhất kế hoạch Wireshark testing Tuần 3 | `docs/ngay14_dac_ta_interface_v2_cho_nhom.md`, `docs/draft_bao_cao_tuan2_bo_sung.md` | *(VD: ...)* |

## Tổng kết Tuần 2

- **Hoàn thành:** 100% mục tiêu đề ra theo kế hoạch gốc (giao thức trao khóa hoàn chỉnh,
  demo 2 peer trao đổi khóa qua kênh RSA, log rõ từng bước).
- **Vượt kỳ vọng ban đầu:** kế hoạch gốc chỉ ghi "chữ ký số/HMAC nếu còn thời gian" — nhóm
  đã hoàn thành đầy đủ chữ ký số RSA-PSS, thêm cả cơ chế fingerprint chống MITM và bộ kiểm
  thử lỗi toàn diện (không có trong yêu cầu tối thiểu).
- **Cột mốc quan trọng nhất:** mã hóa lai lần đầu chạy thành công qua kết nối socket TCP
  thật (Ngày 10), không còn là mô phỏng nội bộ như Tuần 1.
- **Việc cần làm Tuần 3:** ráp nối với module Networking thật của A (thay socket demo tạm),
  kiểm thử bảo mật bằng Wireshark, hoàn thiện báo cáo cuối kỳ và chuẩn bị demo bảo vệ.