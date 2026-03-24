import threading
import time


class AdaptiveResponse:

    def __init__(self, routing_engine,
                 notifier, offline_detector):

        self.router              = routing_engine
        self.notifier            = notifier
        self.offline_detector    = offline_detector
        self.redirected_ips      = set()
        self.suspicious_notified = {}

        print("[RESPONSE] Adaptive Response initialized")

    def respond(self, src_ip, intent, fingerprint=None):

        if intent == "NORMAL":
            self._handle_normal(src_ip)

        elif intent == "SUSPICIOUS":
            self._handle_suspicious(src_ip)

        elif intent == "MALICIOUS":
            self._handle_malicious(src_ip, fingerprint)

    def _handle_normal(self, src_ip):

        path = self.router.best_path()

        print(
            f"[RESPONSE] NORMAL     {src_ip} "
            f"-> {' -> '.join(path)}"
        )

    def _handle_suspicious(self, src_ip):

        path = self.router.monitored_path()

        print(
            f"[RESPONSE] SUSPICIOUS {src_ip} "
            f"-> monitored: {' -> '.join(path)}"
        )

        time.sleep(0.05)

        # Notify Pi once every 30s per IP
        now  = time.time()
        last = self.suspicious_notified.get(src_ip, 0)

        if now - last > 30:

            self.suspicious_notified[src_ip] = now

            threading.Thread(
                target=self._notify_suspicious,
                args=(src_ip,),
                daemon=True
            ).start()

            print(
                f"[RESPONSE] Pi notified "
                f"SUSPICIOUS: {src_ip}"
            )

    def _notify_suspicious(self, src_ip):

        from notifications.local_alert import send_local_pi

        send_local_pi(src_ip, "SUSPICIOUS")

    def _handle_malicious(self, src_ip, fingerprint):

        if src_ip in self.redirected_ips:
            return

        self.redirected_ips.add(src_ip)

        path = self.router.decoy_path()

        print(
            f"[RESPONSE] MALICIOUS  {src_ip} "
            f"-> {' -> '.join(path)}"
        )

        threading.Thread(
            target=self._notify,
            args=(src_ip, fingerprint),
            daemon=True
        ).start()

        threading.Thread(
            target=self._auto_clear,
            args=(src_ip,),
            daemon=True
        ).start()

    def _auto_clear(self, src_ip):

        time.sleep(30)

        self.redirected_ips.discard(src_ip)

        print(
            f"[RESPONSE] Cleared {src_ip} "
            f"from malicious list"
        )

    def _notify(self, src_ip, fingerprint):

        attack_type = "ATTACK_DETECTED"

        from notifications.local_alert import (
            send_cloud_ntfy,
            send_local_ntfy,
            send_local_pi
        )

        from notifications.firebase_alert import (
            send_firebase
        )

        # Always try cloud ntfy first

        cloud_sent = send_cloud_ntfy(
            src_ip,
            attack_type,
            title="ACRDN - Attack Detected!",
            body=f"Attacker IP: {src_ip}\n"
                 f"Action: Redirected to honeypot"
        )

        if not cloud_sent:
            send_local_ntfy(src_ip, attack_type)

        if self.offline_detector.is_online:
            send_firebase(src_ip, attack_type)

        else:
            self.offline_detector.handle_offline_attack(
                src_ip,
                attack_type,
                fingerprint or {}
            )

        # Always alert Pi hardware

        send_local_pi(src_ip, attack_type)