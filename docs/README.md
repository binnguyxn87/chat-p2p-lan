# Module Bảo mật — Tuần 2 (Thành viên B)
### Dự án: Ứng dụng Chat P2P trong mạng LAN — Kiến trúc mã hóa lai RSA + AES

Kế thừa toàn bộ `crypto/rsa_utils.py` và `crypto/aes_utils.py` từ Tuần 1 (không đổi).
Tuần 2 bổ sung: giao thức mạng, quản lý phiên đa peer, chữ ký số, fingerprint, và test
tích hợp qua socket TCP thật.

## Cài đặt

```bash
pip install pycryptodome --break-system-packages
```

## Cấu trúc thư mục

```
week2_member_B/
├── crypto/
│   ├── rsa_utils.py            # (kế thừa Tuần 1)
│   ├── aes_utils.py            # (kế thừa Tuần 1)
│   ├── protocol.py             # MỚI: đóng gói/giải gói JSON cho socket
│   ├── signature_utils.py      # MỚI: ký số & xác thực RSA-PSS
│   └── fingerprint_utils.py    # MỚI: vân tay public key chống MITM
├── session/
│   └── session_manager.py      # MỚI: máy trạng thái bắt tay, quản lý nhiều peer
├── tests/
│   ├── day8_test_protocol_serialization.py
│   ├── day9_test_session_handshake.py
│   ├── day10_test_socket_integration.py     # test qua socket TCP THẬT
│   ├── day11_test_digital_signature.py
│   ├── day12_test_fingerprint_and_reconnect.py
│   └── day13_test_comprehensive_edge_cases.py
├── docs/
│   ├── ngay14_dac_ta_interface_v2_cho_nhom.md
│   └── draft_bao_cao_tuan2_bo_sung.md
└── NHAT_KY_TUAN_2.md
```

## Cách chạy

```bash
python3 tests/day8_test_protocol_serialization.py
python3 tests/day9_test_session_handshake.py
python3 tests/day10_test_socket_integration.py
python3 tests/day11_test_digital_signature.py
python3 tests/day12_test_fingerprint_and_reconnect.py
python3 tests/day13_test_comprehensive_edge_cases.py
```

Script `day10` mở cổng TCP `51234` trên `127.0.0.1` — nếu báo lỗi "Address already in use",
chờ vài giây rồi chạy lại, hoặc đổi số `PORT` trong file.

**Nên chụp màn hình output của từng ngày** để làm minh chứng đính kèm báo cáo/nhật ký.

## Việc quan trọng nhất cần nhớ khi họp nhóm Tuần 3

File `docs/ngay14_dac_ta_interface_v2_cho_nhom.md` chứa đoạn code mẫu ĐẦY ĐỦ để A cắm
thẳng vào vòng lặp socket của mình — mang file này ra họp nhóm đầu Tuần 3.