import base64
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt, export_public_key, import_public_key
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
from crypto.signature_utils import sign_message, verify_signature


class CryptoBridge:
    """
    Cầu nối module Bảo mật (RSA + AES + chữ ký số) vào module Networking (Peer).
    Luồng bắt tay:
      1. Khi có kết nối mới, cả 2 bên gửi PUBKEY (public key RSA) cho nhau.
      2. Chỉ bên "chủ động kết nối" (is_initiator=True) mới tạo khóa AES phiên,
         mã hóa nó bằng RSA public key của đối phương, gửi qua KEY_EXCHANGE.
      3. Bên nhận KEY_EXCHANGE giải mã bằng RSA private key -> có session key.
      4. Từ đó, mọi tin nhắn MESSAGE được mã hóa AES-256-GCM + kèm chữ ký số RSA.
    """

    def __init__(self, peer):
        self.peer = peer
        self.private_key, self.public_key = generate_rsa_keypair()
        self.peer_public_keys = {}   # addr -> RSA public key đối phương
        self.session_keys = {}       # addr -> khóa AES phiên (bytes)
        self.is_initiator = {}       # addr -> bool
        self.ready = {}              # addr -> bool
        self.on_status_change = None  # callback tuỳ chọn cho UI: (addr, status_str)
        self.on_wire_log = None       # callback demo bảo mật: (direction, addr, raw_json_str)
        self.peer_names = {}          # addr -> tên hiển thị của đối phương

        peer.encrypt_hook = self._encrypt
        peer.decrypt_hook = self._decrypt
        peer.on_peer_connected = self._on_peer_connected
        peer.on_peer_disconnected = self._on_peer_disconnected
        peer.crypto_bridge_handler = self._handle_control_message

    # ---------- BẮT TAY ----------

    def _on_peer_connected(self, addr, initiator):
        self.ready[addr] = False
        self.is_initiator[addr] = initiator
        self.peer.send_control(addr, "PUBKEY", export_public_key(self.public_key))
        self._notify(addr, "Đang bắt tay...")

    def _on_peer_disconnected(self, addr):
        self.peer_public_keys.pop(addr, None)
        self.session_keys.pop(addr, None)
        self.ready.pop(addr, None)
        self.is_initiator.pop(addr, None)
        self._notify(addr, "Đã ngắt kết nối")

    def _handle_control_message(self, msg_type, sender, payload, addr):
        if msg_type == "PUBKEY":
            self.peer_public_keys[addr] = import_public_key(payload)
            self.peer_names[addr] = sender
            if self.is_initiator.get(addr, False) and addr not in self.session_keys:
                self._create_and_send_session_key(addr)

        elif msg_type == "KEY_EXCHANGE":
            encrypted_key = base64.b64decode(payload)
            session_key = rsa_decrypt(self.private_key, encrypted_key)
            self.session_keys[addr] = session_key
            self.ready[addr] = True
            self._notify(addr, "Đã mã hóa (sẵn sàng)")

    def _create_and_send_session_key(self, addr):
        if addr not in self.peer_public_keys:
            return
        session_key = generate_aes_key()
        self.session_keys[addr] = session_key
        encrypted = rsa_encrypt(self.peer_public_keys[addr], session_key)
        self.peer.send_control(addr, "KEY_EXCHANGE", base64.b64encode(encrypted).decode('utf-8'))
        self.ready[addr] = True
        self._notify(addr, "Đã mã hóa (sẵn sàng)")

    def _notify(self, addr, status):
        if self.on_status_change:
            self.on_status_change(addr, status)

    def is_ready(self, addr):
        return self.ready.get(addr, False)

    def get_display_name(self, addr):
        return self.peer_names.get(addr, f"{addr[0]}:{addr[1]}")

    # ---------- MÃ HÓA / GIẢI MÃ TIN NHẮN ----------

    def _encrypt(self, text, addr):
        if not self.is_ready(addr):
            return text
        enc = aes_encrypt(self.session_keys[addr], text)
        signature = sign_message(self.private_key, text)
        raw = json.dumps({
            "n": base64.b64encode(enc["nonce"]).decode('utf-8'),
            "c": base64.b64encode(enc["ciphertext"]).decode('utf-8'),
            "t": base64.b64encode(enc["tag"]).decode('utf-8'),
            "s": base64.b64encode(signature).decode('utf-8'),
        })
        if self.on_wire_log:
            self.on_wire_log("GỬI ĐI (OUT)", addr, raw)
        return raw

    def _decrypt(self, payload, addr):
        if not self.is_ready(addr):
            return payload
        if self.on_wire_log:
            self.on_wire_log("NHẬN VỀ (IN)", addr, payload)
        try:
            data = json.loads(payload)
            enc = {
                "nonce": base64.b64decode(data["n"]),
                "ciphertext": base64.b64decode(data["c"]),
                "tag": base64.b64decode(data["t"]),
            }
            plaintext = aes_decrypt(self.session_keys[addr], enc)

            signature = base64.b64decode(data["s"])
            sender_pubkey = self.peer_public_keys.get(addr)
            if sender_pubkey and not verify_signature(sender_pubkey, plaintext, signature):
                return "[CẢNH BÁO] Chữ ký không hợp lệ - tin nhắn có thể bị giả mạo!"

            return plaintext
        except Exception:
            return "[LỖI GIẢI MÃ]"
