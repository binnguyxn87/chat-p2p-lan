import json
import datetime


def create_message(msg_type, sender, payload):
    message = {
        "type": msg_type,
        "sender": sender,
        "payload": payload,
        "timestamp": datetime.datetime.now().isoformat()
    }
    return json.dumps(message)


def parse_message(raw_data):
    try:
        return json.loads(raw_data)
    except json.JSONDecodeError:
        return None
