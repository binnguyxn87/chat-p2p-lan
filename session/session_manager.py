"""
CHỨC NĂNG:
Tuần 1, demo hybrid chỉ xử lý ĐÚNG 2 peer, làm 1 lần, theo kịch bản cố định.
Thực tế ứng dụng chat P2P có thể kết nối với NHIỀU peer cùng lúc (khớp với việc
A đang làm multi-connection ở tuần 2), mỗi peer cần một session key RIÊNG, và
quá trình bắt tay (handshake) cần được theo dõi qua nhiều bước chứ không làm
xong ngay trong 1 lần gọi hàm. Module này quản lý việc đó bằng một máy trạng thái
(state machine) đơn giản.
 
SƠ ĐỒ TRẠNG THÁI CỦA MỘT PHIÊN (PeerSession):
 
    NEW --(nhận public key của peer)--> PUBKEY_RECEIVED
                                              |
                        (mình là bên chủ động: tự sinh + mã hóa + gửi session key)
                                              v
                                          KEY_SENT --(peer xác nhận)--> ESTABLISHED
 
    NEW --(mình là bên chủ động, gửi public key trước)--> PUBKEY_SENT
                                              |
                              (nhận được session key đã mã hóa từ peer)
                                              v
                                         ESTABLISHED (giải mã ngay ra session key)
"""
 
from enum import Enum
 
from crypto.rsa_utils import rsa_encrypt, rsa_decrypt
from crypto.aes_utils import generate_aes_key
 
 
class SessionState(Enum):
    NEW = "NEW"
    PUBKEY_SENT = "PUBKEY_SENT"
    PUBKEY_RECEIVED = "PUBKEY_RECEIVED"
    KEY_SENT = "KEY_SENT"
    ESTABLISHED = "ESTABLISHED"
 
 
class PeerSession:
    """Đại diện cho trạng thái bảo mật của kết nối với MỘT peer cụ thể."""
 
    def __init__(self, peer_id: str):
        self.peer_id = peer_id
        self.state = SessionState.NEW
        self.peer_public_key = None
        self.session_key = None
        self.is_initiator = False  # True nếu mình là bên chủ động sinh session key
 
    def mark_pubkey_sent(self):
        if self.state == SessionState.NEW:
            self.state = SessionState.PUBKEY_SENT
 
    def set_peer_public_key(self, peer_public_key):
        """Gọi khi nhận được gói tin pubkey_exchange từ peer."""
        self.peer_public_key = peer_public_key
        if self.state in (SessionState.NEW, SessionState.PUBKEY_SENT):
            self.state = SessionState.PUBKEY_RECEIVED
 
    def generate_and_encrypt_session_key(self) -> bytes:
        """Bên CHỦ ĐỘNG gọi hàm này: tự sinh session key AES, mã hóa bằng RSA
        public key của peer, trả về bytes đã mã hóa để gửi đi."""
        if self.peer_public_key is None:
            raise RuntimeError(
                f"[{self.peer_id}] Chưa có public key của peer, "
                "phải nhận pubkey_exchange trước khi trao session key."
            )
        self.session_key = generate_aes_key()
        encrypted = rsa_encrypt(self.peer_public_key, self.session_key)
        self.is_initiator = True
        self.state = SessionState.KEY_SENT
        return encrypted
 
    def receive_encrypted_session_key(self, my_private_key, encrypted_session_key: bytes):
        """Bên BỊ ĐỘNG gọi hàm này khi nhận gói tin key_exchange: giải mã ngay
        ra session key bằng private key của chính mình."""
        self.session_key = rsa_decrypt(my_private_key, encrypted_session_key)
        self.state = SessionState.ESTABLISHED
 
    def confirm_established(self):
        """Bên chủ động gọi sau khi gửi xong session key (coi như phiên đã sẵn sàng
        để chat - không cần chờ ACK riêng trong phạm vi đồ án)."""
        if self.state == SessionState.KEY_SENT:
            self.state = SessionState.ESTABLISHED
 
    def is_ready(self) -> bool:
        return self.state == SessionState.ESTABLISHED and self.session_key is not None
 
    def invalidate(self):
        """QUAN TRỌNG: gọi khi phát hiện peer ngắt kết nối. Không được tái sử dụng
        session key cũ khi peer kết nối lại - phải bắt tay lại từ đầu để đảm bảo
        an toàn (tránh trường hợp kẻ tấn công chiếm được session key cũ)."""
        self.state = SessionState.NEW
        self.session_key = None
        self.peer_public_key = None
        self.is_initiator = False
 
    def __repr__(self):
        return f"<PeerSession peer={self.peer_id} state={self.state.value} ready={self.is_ready()}>"
 
 
class SessionManager:
    """Quản lý PeerSession cho TẤT CẢ peer đang kết nối cùng lúc."""
 
    def __init__(self):
        self._sessions = {}  # peer_id -> PeerSession
 
    def get_or_create(self, peer_id: str) -> PeerSession:
        if peer_id not in self._sessions:
            self._sessions[peer_id] = PeerSession(peer_id)
        return self._sessions[peer_id]
 
    def remove(self, peer_id: str):
        self._sessions.pop(peer_id, None)
 
    def list_established_peers(self):
        return [pid for pid, s in self._sessions.items() if s.is_ready()]
 
    def list_all(self):
        return list(self._sessions.values())
 
    def __len__(self):
        return len(self._sessions)