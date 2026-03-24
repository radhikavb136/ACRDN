import sys
import time as time_module
import threading
import time

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from logger import init_log, log_event
from scapy.all import sniff, IP, TCP, UDP

from config import *
from database.db_manager     import init_db
from core.routing_engine     import RoutingEngine
from core.intent_classifier  import IntentClassifier
from core.self_learner       import SelfLearner
from core.adaptive_response  import AdaptiveResponse
from core.offline_detector   import OfflineDetector
from honeypot.fake_server    import start_honeypot
from dashboard.app           import (
    start_dashboard, update_dashboard
)
import notifications.firebase_alert as firebase
import notifications.local_alert    as local_notify


class Notifier:
    def send_firebase(self, *args, **kwargs):
        return firebase.send_firebase(*args, **kwargs)
    def send_local_pi(self, *args):
        return local_notify.send_local_pi(*args)
    def send_local_ntfy(self, *args):
        return local_notify.send_local_ntfy(*args)


print("\n" + "="*50)
print("  ACRDN - Starting Up")
print("="*50 + "\n")

init_db()
init_log()

notifier          = Notifier()
routing_engine    = RoutingEngine()
intent_classifier = IntentClassifier()
self_learner      = SelfLearner()
offline_detector  = OfflineDetector(notifier)
adaptive_response = AdaptiveResponse(
    routing_engine, notifier, offline_detector
)

recently_processed = {}
attacks_today      = 0


def reset_ip_later(src_ip):
    time.sleep(30)
    intent_classifier.reset_ip(src_ip)
    print(f"[MAIN] Reset tracker for {src_ip}")


def process_packet(packet):
    global attacks_today

    if IP not in packet:
        return

    src_ip = packet[IP].src

    if src_ip in WHITELIST_IPS:
        return

    intent = intent_classifier.update(packet)

    now  = time_module.time()
    last = recently_processed.get(src_ip, 0)
    if now - last < 1.0:
        return
    recently_processed[src_ip] = now

    score       = intent_classifier.get_score(src_ip)
    fingerprint = intent_classifier.get_fingerprint(src_ip)

    known, attack_name = self_learner.is_known_attack(
        fingerprint
    )
    if known and intent != "MALICIOUS":
        print(f"[MAIN] Known attack! Escalating to MALICIOUS")
        intent = "MALICIOUS"

    routing_engine.record_packet(src_ip, intent)

    start_time = time_module.time()
    adaptive_response.respond(src_ip, intent, fingerprint)
    response_ms = round(
        (time_module.time() - start_time) * 1000, 2
    )

    log_event(
        src_ip, intent, score,
        len(fingerprint.get("ports", [])),
        fingerprint.get("syn_count", 0),
        intent,
        routing_engine.best_path(),
        response_ms
    )

    if intent == "MALICIOUS":
        attacks_today += 1
        if not known:
            self_learner.learn(
                fingerprint,
                attack_name or "PORT_SCAN"
            )
        threading.Thread(
            target=reset_ip_later,
            args=(src_ip,),
            daemon=True
        ).start()

    all_intents = intent_classifier.get_all_intents()
    connections = {}
    for ip, int_ in all_intents.items():
        connections[ip] = {
            "intent": int_,
            "score":  intent_classifier.get_score(ip)
        }

    update_dashboard({
        "connections":     connections,
        "graph":           routing_engine.get_graph_data(),
        "best_path":       routing_engine.best_path(),
        "patterns_count":  self_learner.get_stats()[
                               "total_patterns"],
        "attacks_today":   attacks_today,
        "honeypot_active": len(
            adaptive_response.redirected_ips) > 0
    })


def start_sniffing():
    print(f"\n[MAIN] Sniffing on: {NETWORK_INTERFACE}")
    print(f"[MAIN] Monitoring started...\n")
    sniff(
        iface=NETWORK_INTERFACE,
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":

    offline_detector.start()

    threading.Thread(
        target=start_honeypot,
        args=(HONEYPOT_PORT,),
        daemon=True
    ).start()

    threading.Thread(
        target=start_dashboard,
        args=(DASHBOARD_PORT,),
        daemon=True
    ).start()

    time.sleep(3)

    print("\n" + "="*50)
    print("  ALL SYSTEMS RUNNING")
    print(f"  Dashboard : http://localhost:{DASHBOARD_PORT}")
    print(f"  Honeypot  : port {HONEYPOT_PORT}")
    print(f"  Interface : {NETWORK_INTERFACE}")
    print("="*50 + "\n")

    start_sniffing()