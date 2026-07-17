import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto.rsa_utils import generate_rsa_keypair
from crypto.aes_utils import aes_encrypt
from crypto.signature_utils import sign_message, verify_signature
from session.session_manager import SessionManager
from session import protocol as sp


class CryptoBridge:
    """
    Cầu nối giữa module Networking (A) và module Bảo mật (B).
    Dùng đúng SessionManager/PeerSession và session.protocol do B viết để
    quản lý trạng thái bắt tay và đóng gói dữ liệu mã hóa.
    """

    def __init__(self, peer):
        self.peer = peer
        self.private_key, self.public_key = generate_rsa_keypair()
        self.manager = SessionManager()

        peer.encrypt_hook = self._encrypt
        peer.decrypt_hook = self._decrypt
        peer.on_peer_connected = self._on_peer_connected
        peer.on_peer_disconnected = self._on_peer_disconnected

    def _pid(self, addr):
        return f"{addr[0]}:{addr[1]}"

    # ---------- BẮT TAY ----------

    def _on_peer_connected(self, addr, is_initiator):
        pid = self._pid(addr)
        session = self.manager.get_or_create(pid)
        session.is_initiator = is_initiator
        self._send_control(addr, "PUBKEY", self.public_key.export_key().decode('utf-8'))
        session.mark_pubkey_sent()

    def _on_peer_disconnected(self, addr):
        pid = self._pid(addr)
        session = self.manager.get_or_create(pid)
        session.invalidate()
        self.manager.remove(pid)

    def handle_control_message(self, msg_type, sender, payload, addr):
        """peer.py gọi hàm này khi nhận gói tin loại PUBKEY / KEY_EXCHANGE."""
        pid = self._pid(addr)
        session = self.manager.get_or_create(pid)

        if msg_type == "PUBKEY":
            from Crypto.PublicKey import RSA
            session.set_peer_public_key(RSA.import_key(payload))
            print(f"[CryptoBridge] Đã nhận public key từ {addr}")

            if session.is_initiator and session.session_key is None:
                encrypted = session.generate_and_encrypt_session_key()
                self._send_control(addr, "KEY_EXCHANGE", sp.encode_bytes(encrypted))
                session.confirm_established()
                print(f"[CryptoBridge] Đã tạo và gửi session key AES cho {addr}")

        elif msg_type == "KEY_EXCHANGE":
            encrypted_key = sp.decode_bytes(payload)
            session.receive_encrypted_session_key(self.private_key, encrypted_key)
            print(f"[CryptoBridge] Bắt tay hoàn tất với {addr} — sẵn sàng chat mã hóa")

    def _send_control(self, addr, msg_type, payload):
        from protocol import create_message
        packet = create_message(msg_type, self.peer.my_name, payload)
        if addr in self.peer.connections:
            try:
                self.peer.connections[addr].send(packet.encode('utf-8'))
            except Exception:
                pass

    def is_ready(self, addr):
        return self.manager.get_or_create(self._pid(addr)).is_ready()

    # ---------- ENCRYPT / DECRYPT (dùng session.protocol của B) ----------

    def _encrypt(self, text, addr):
        session = self.manager.get_or_create(self._pid(addr))
        if not session.is_ready():
            return text
        enc = aes_encrypt(session.session_key, text)
        signature = sign_message(self.private_key, text)
        msg = sp.build_chat_message(self.peer.my_name, enc, signature)
        return sp.serialize_message(msg)

    def _decrypt(self, payload, addr):
        session = self.manager.get_or_create(self._pid(addr))
        if not session.is_ready():
            return payload
        try:
            msg = sp.parse_message(payload)
            plaintext = sp.safe_decrypt_chat_message(session.session_key, msg)
            signature = sp.extract_signature(msg)
            if signature and session.peer_public_key:
                if not verify_signature(session.peer_public_key, plaintext, signature):
                    return "[CẢNH BÁO] Chữ ký không hợp lệ - tin nhắn có thể bị giả mạo!"
            return plaintext
        except sp.CryptoProtocolError as e:
            return f"[LỖI GIẢI MÃ] {e}"
        except Exception:
            return "[LỖI GIẢI MÃ]"