import requests
from config import RASPBERRY_PI_IP, PI_LISTENER_PORT

NTFY_CLOUD = "https://ntfy.sh"
NTFY_TOPIC = "acrdn-radhika"    # same as phone

def send_cloud_ntfy(src_ip, attack_type,
                    title=None, body=None):
    try:
        requests.post(
            f"{NTFY_CLOUD}/{NTFY_TOPIC}",
            data=body or
                 f"Attack: {attack_type} "
                 f"from {src_ip}",
            headers={
                "Title":    title or
                            "ACRDN Security Alert",
                "Priority": "urgent",
                "Tags":     "warning,shield"
            },
            timeout=5
        )
        print("[NOTIFY] Phone notified via ntfy!")
        return True
    except Exception as e:
        print(f"[NOTIFY] ntfy failed: {e}")
        return False

def send_local_ntfy(src_ip, attack_type):
    try:
        requests.post(
            f"http://{RASPBERRY_PI_IP}:8080/"
            f"{NTFY_TOPIC}",
            data=f"OFFLINE: {attack_type} "
                 f"from {src_ip}",
            headers={
                "Title":    "ACRDN Offline Alert",
                "Priority": "urgent",
                "Tags":     "warning"
            },
            timeout=3
        )
        print("[NOTIFY] Local ntfy sent!")
        return True
    except Exception as e:
        print(f"[NOTIFY] Local ntfy failed: {e}")
        return False

def send_local_pi(src_ip, attack_type):
    try:
        requests.post(
            f"http://{RASPBERRY_PI_IP}:"
            f"{PI_LISTENER_PORT}/alert",
            json={
                "attacker_ip": src_ip,
                "attack_type": attack_type
            },
            timeout=3
        )
        print("[NOTIFY] Pi alerted!")
        return True
    except Exception as e:
        print(f"[NOTIFY] Pi alert failed: {e}")
        return False