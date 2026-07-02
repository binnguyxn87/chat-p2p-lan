import json
import datetime

def create_message(msg_type, sender, payload):
    """
    Đóng gói 1 message theo chuẩn chung của cả nhóm.
    msg_type: loại gói tin - "MESSAGE", "KEY_EXCHANGE", "PEER_ANNOUNCE", "PEER_LEAVE"
    sender: tên/id của người gửi
    payload: nội dung thực sự (có thể là text thường, hoặc ciphertext của B)
    """
    message = {
        "type": msg_type,
        "sender": sender,
        "payload": payload,
        "timestamp": datetime.datetime.now().isoformat()
    }
    # Chuyển dict thành chuỗi JSON để gửi qua mạng được (mạng chỉ truyền được bytes/string)
    return json.dumps(message)

def parse_message(raw_data):
    """
    Nhận chuỗi JSON thô từ mạng, chuyển ngược lại thành dict để dùng trong code.
    """
    try:
        return json.loads(raw_data)
    except json.JSONDecodeError:
        print("[LỖI] Không đọc được message, dữ liệu không đúng định dạng JSON")
        return None