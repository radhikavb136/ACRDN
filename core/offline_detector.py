import threading
import time
import requests
from database.db_manager import (
    get_pending_notifications,
    mark_notified,
    save_offline_attack
)


class OfflineDetector:

    def __init__(self, notifier):
        self.notifier       = notifier
        self.is_online      = False
        self.check_interval = 10
        print("[OFFLINE] Offline Detector initialized")

    def start(self):
        t = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        t.start()
        print("[OFFLINE] Connectivity monitor started")

    def _monitor_loop(self):
        last_status = None
        while True:
            self.is_online = self._check_internet()

            # Only print when status changes
            if self.is_online != last_status:
                if self.is_online:
                    print("[OFFLINE] Online mode active")
                    self._flush_pending()
                else:
                    print("[OFFLINE] Offline mode active")
                last_status = self.is_online

            time.sleep(self.check_interval)

    def _check_internet(self):
        urls = [
            "https://ntfy.sh",
            "http://google.com",
            "http://8.8.8.8"
        ]
        for url in urls:
            try:
                requests.get(url, timeout=3)
                return True
            except:
                continue
        return False

    def _flush_pending(self):
        pending = get_pending_notifications()
        if not pending:
            return
        print(f"[OFFLINE] Sending {len(pending)} "
              f"pending alerts...")
        from notifications.local_alert import send_cloud_ntfy
        for attack in pending:
            attack_id   = attack[0]
            src_ip      = attack[1]
            attack_type = attack[2]
            success = send_cloud_ntfy(
                src_ip, attack_type,
                title="Missed Attack Alert",
                body=f"Offline attack: "
                     f"{attack_type} from {src_ip}"
            )
            if success:
                mark_notified(attack_id)
                print(f"[OFFLINE] Sent pending: {src_ip}")

    def handle_offline_attack(self, src_ip,
                               attack_type, details):
        print(f"[OFFLINE] Attack logged: {attack_type}")
        save_offline_attack(src_ip, attack_type, details)
        from notifications.local_alert import (
            send_local_pi, send_local_ntfy
        )
        send_local_pi(src_ip, attack_type)
        send_local_ntfy(src_ip, attack_type)
