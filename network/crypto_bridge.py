import base64
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from crypto.aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
from crypto.signature_utils import sign_message, verify_signature


class CryptoBridge:
    def __init__(self, peer):
        self.peer = peer
        self.private_key, self.public_key = generate_rsa_keypair()
        self.peer_public_keys = {}
        self.session_keys = {}
        self.ready = {}
        self.is_initiator = {}   # addr -> True nếu mình là bên chủ động connect_to

        peer.encrypt_hook = self._encrypt
        peer.decrypt_hook = self._decrypt
        peer.on_peer_connected = self._on_peer_connected
        peer.on_peer_disconnected = self._on_peer_disconnected

    def _on_peer_connected(self, addr, is_initiator):
        self.ready[addr] = False
        self.is_initiator[addr] = is_initiator
        pub_pem = self.public_key.export_key().decode('utf-8')
        self._send_control(addr, "PUBKEY", pub_pem)

    def _on_peer_disconnected(self, addr):
        self.peer_public_keys.pop(addr, None)
        self.session_keys.pop(addr, None)
        self.ready.pop(addr, None)
        self.is_initiator.pop(addr, None)

    def handle_control_message(self, msg_type, sender, payload, addr):
        if msg_type == "PUBKEY":
            from Crypto.PublicKey import RSA
            self.peer_public_keys[addr] = RSA.import_key(payload)
            print(f"[CryptoBridge] Đã nhận public key từ {addr}")
            # CHỈ bên chủ động (initiator) mới tạo và gửi session key,
            # tránh 2 bên cùng tạo khóa khác nhau (race condition gây lệch khóa)
            if self.is_initiator.get(addr, False) and addr not in self.session_keys:
                self._create_and_send_session_key(addr)

        elif msg_type == "KEY_EXCHANGE":
            encrypted_key = base64.b64decode(payload)
            session_key = rsa_decrypt(self.private_key, encrypted_key)
            self.session_keys[addr] = session_key
            self.ready[addr] = True
            print(f"[CryptoBridge] Bắt tay hoàn tất với {addr} — sẵn sàng chat mã hóa")

    def _create_and_send_session_key(self, addr):
        if addr not in self.peer_public_keys:
            return
        session_key = generate_aes_key()
        self.session_keys[addr] = session_key
        encrypted = rsa_encrypt(self.peer_public_keys[addr], session_key)
        payload = base64.b64encode(encrypted).decode('utf-8')
        self._send_control(addr, "KEY_EXCHANGE", payload)
        self.ready[addr] = True
        print(f"[CryptoBridge] Đã tạo và gửi session key AES cho {addr}")

    def _send_control(self, addr, msg_type, payload):
        from protocol import create_message
        packet = create_message(msg_type, self.peer.my_name, payload)
        if addr in self.peer.connections:
            try:
                self.peer.connections[addr].send(packet.encode('utf-8'))
            except Exception:
                pass

    def is_ready(self, addr):
        return self.ready.get(addr, False)

    def _encrypt(self, text, addr):
        if not self.is_ready(addr):
            return text
        enc = aes_encrypt(self.session_keys[addr], text)
        signature = sign_message(self.private_key, text)
        return json.dumps({
            "nonce": base64.b64encode(enc["nonce"]).decode('utf-8'),
            "ciphertext": base64.b64encode(enc["ciphertext"]).decode('utf-8'),
            "tag": base64.b64encode(enc["tag"]).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
        })

    def _decrypt(self, payload, addr):
        if not self.is_ready(addr):
            return payload
        try:
            data = json.loads(payload)
            enc = {
                "nonce": base64.b64decode(data["nonce"]),
                "ciphertext": base64.b64decode(data["ciphertext"]),
                "tag": base64.b64decode(data["tag"]),
            }
            plaintext = aes_decrypt(self.session_keys[addr], enc)

            signature = base64.b64decode(data["signature"])
            sender_pubkey = self.peer_public_keys.get(addr)
            if sender_pubkey and not verify_signature(sender_pubkey, plaintext, signature):
                return "[CẢNH BÁO] Chữ ký không hợp lệ - tin nhắn có thể bị giả mạo!"

            return plaintext
        except Exception:
            return "[LỖI GIẢI MÃ]"