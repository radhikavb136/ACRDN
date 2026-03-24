import firebase_admin
from firebase_admin import credentials, messaging
import os

_initialized = False

def _init():
    global _initialized
    if not _initialized:
        path = os.path.join(
            os.path.dirname(__file__),
            "..", "firebase_creds.json"
        )
        cred = credentials.Certificate(path)
        firebase_admin.initialize_app(cred)
        _initialized = True
        print("[FIREBASE] Initialized successfully")

def send_firebase(src_ip, attack_type,
                  title=None, body=None):
    try:
        _init()
        message = messaging.Message(
            notification=messaging.Notification(
                title=title or
                      "ACRDN Security Alert",
                body=body or
                     f"{attack_type} from {src_ip}"
            ),
            topic="acrdn-alerts"
        )
        response = messaging.send(message)
        print(f"[FIREBASE] Sent: {response}")
        return True
    except Exception as e:
        print(f"[FIREBASE] Error: {e}")
        return False