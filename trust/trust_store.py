"""
Ngày 17 
CHỨC NĂNG: Cài đặt mô hình "Trust On First Use" (TOFU) - giải quyết hạn chế đã
nêu trong báo cáo Tuần 2 (mục 10.1): "chưa có cảnh báo tự động nếu fingerprint
của một peer quen thuộc bỗng thay đổi giữa 2 lần kết nối".

NGUYÊN LÝ TOFU (giống SSH "known_hosts", hoặc Signal khi Safety Number đổi):
  - Lần đầu kết nối với 1 peer_id: LƯU LẠI fingerprint của họ, coi là "tin cậy".
  - Lần sau kết nối lại với CÙNG peer_id: so sánh fingerprint mới nhận với
    fingerprint đã lưu.
      + Khớp -> bình thường, không cảnh báo.
      + KHÔNG khớp -> CẢNH BÁO NGAY LẬP TỨC, vì đây là dấu hiệu rất đáng ngờ:
        hoặc peer đã cài lại ứng dụng (đổi khóa hợp lệ), HOẶC đang bị tấn công
        Man-in-the-Middle (kẻ tấn công giả danh peer đó với khóa khác).

LƯU Ý: TOFU không ngăn chặn được MITM ở NGAY LẦN ĐẦU kết nối (vì
lúc đó chưa có gì để so sánh) - đây là hạn chế đã biết của mô hình TOFU nói
chung (kể cả SSH cũng có hạn chế này). TOFU chỉ bảo vệ từ lần kết nối THỨ HAI
trở đi. Trình bày rõ giới hạn này khi thuyết trình để thể hiện hiểu đúng bản chất.
"""

import json
import os

from crypto.fingerprint_utils import get_public_key_fingerprint


class TrustDecision:
    NEW = "NEW"          # lần đầu gặp peer này, đã lưu lại fingerprint
    MATCH = "MATCH"      # fingerprint khớp với lần trước - an toàn
    MISMATCH = "MISMATCH"  # fingerprint KHÁC lần trước - CẢNH BÁO


class TrustStore:
    """Lưu trữ fingerprint đã biết của từng peer, dùng file JSON đơn giản
    (đủ dùng cho phạm vi đồ án; hệ thống thực tế có thể dùng database)."""

    def __init__(self, store_path: str):
        self.store_path = store_path
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.store_path):
            with open(self.store_path, "r") as f:
                return json.load(f)
        return {}

    def _save(self):
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
        with open(self.store_path, "w") as f:
            json.dump(self._data, f, indent=2)

    def check_and_update(self, peer_id: str, public_key_pem: bytes):
        """Hàm chính: gọi mỗi khi nhận được public key của 1 peer (lúc bắt tay).

        Returns:
            (quyet_dinh, fingerprint_moi, fingerprint_cu_hoac_None)
        """
        fingerprint_moi = get_public_key_fingerprint(public_key_pem)

        if peer_id not in self._data:
            self._data[peer_id] = fingerprint_moi
            self._save()
            return TrustDecision.NEW, fingerprint_moi, None

        fingerprint_cu = self._data[peer_id]
        if fingerprint_cu == fingerprint_moi:
            return TrustDecision.MATCH, fingerprint_moi, fingerprint_cu
        else:
            # KHÔNG tự động ghi đè fingerprint cũ khi phát hiện mismatch -
            # phải có xác nhận thủ công của người dùng trước (ra khỏi phạm vi
            # đồ án 3 tuần, nhưng cần nêu rõ đây là hướng phát triển tiếp theo).
            return TrustDecision.MISMATCH, fingerprint_moi, fingerprint_cu

    def force_update(self, peer_id: str, public_key_pem: bytes):
        """Chỉ gọi khi người dùng ĐÃ XÁC NHẬN THỦ CÔNG rằng fingerprint mới là
        hợp lệ (VD: bạn của mình báo đã cài lại ứng dụng)."""
        self._data[peer_id] = get_public_key_fingerprint(public_key_pem)
        self._save()
