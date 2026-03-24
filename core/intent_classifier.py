import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP


class IntentClassifier:

    def __init__(self):
        self.tracker = defaultdict(lambda: {
            "ports":         set(),
            "syn_count":     0,
            "request_count": 0,
            "first_seen":    time.time(),
            "last_seen":     time.time(),
            "bytes_sent":    0,
            "failed":        0
        })
        self.intent_cache = {}
        self.score_cache  = {}
        print("[CLASSIFIER] Intent Classifier initialized")


    def update(self, packet):
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        t      = self.tracker[src_ip]

        t["last_seen"]      = time.time()
        t["request_count"] += 1
        t["bytes_sent"]    += len(packet)

        if TCP in packet:
            t["ports"].add(packet[TCP].dport)
            if packet[TCP].flags == "S":
                t["syn_count"] += 1

        if UDP in packet:
            t["ports"].add(packet[UDP].dport)

        score  = self.calculate_score(src_ip)
        intent = self.score_to_intent(score)

        self.score_cache[src_ip]  = score
        self.intent_cache[src_ip] = intent

        return intent


    def calculate_score(self, src_ip):
        t     = self.tracker[src_ip]
        score = 0

        # Port scanning
        ports = len(t["ports"])
        if ports >= 2:   score += 10
        if ports >= 5:   score += 15
        if ports >= 15:  score += 25
        if ports >= 30:  score += 35

        # SYN packets
        if t["syn_count"] >= 10:  score += 15
        if t["syn_count"] >= 50:  score += 25
        if t["syn_count"] >= 100: score += 35

        # Request rate per second
        duration = max(1, time.time() - t["first_seen"])
        rate     = t["request_count"] / duration
        if rate >= 2:   score += 10
        if rate >= 10:  score += 20
        if rate >= 30:  score += 30

        # Data volume
        if t["bytes_sent"] > 500_000:
            score += 10

        return min(score, 100)


    def score_to_intent(self, score):
        if score < 15:
            return "NORMAL"
        if score < 60:
            return "SUSPICIOUS"
        return "MALICIOUS"


    def get_intent(self, src_ip):
        return self.intent_cache.get(src_ip, "NORMAL")


    def get_score(self, src_ip):
        return self.score_cache.get(src_ip, 0)


    def get_fingerprint(self, src_ip):
        t        = self.tracker[src_ip]
        duration = max(1, time.time() - t["first_seen"])

        return {
            "ports":        list(t["ports"]),
            "syn_count":    t["syn_count"],
            "request_rate": round(
                t["request_count"] / duration, 2
            ),
            "duration":     round(duration, 2),
            "bytes":        t["bytes_sent"]
        }


    # ─────────────────────────────────────
    # ML FEATURE EXTRACTION (NEW)
    # ─────────────────────────────────────
    def get_ml_features(self, src_ip):
        """
        Returns a feature vector for ML model
        """

        t        = self.tracker[src_ip]
        duration = max(1, time.time() - t["first_seen"])

        return [
            len(t["ports"]),               # unique ports scanned
            t["syn_count"],                # SYN packets
            t["request_count"] / duration, # request rate
            t["bytes_sent"],               # data volume
            duration                       # session length
        ]


    def get_all_intents(self):
        return dict(self.intent_cache)


    def reset_ip(self, src_ip):
        if src_ip in self.tracker:
            del self.tracker[src_ip]

        if src_ip in self.intent_cache:
            del self.intent_cache[src_ip]

        if src_ip in self.score_cache:
            del self.score_cache[src_ip]