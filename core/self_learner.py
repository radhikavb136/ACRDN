import json
from database.db_manager import save_pattern, get_all_patterns

class SelfLearner:

    def __init__(self):
        self.patterns = []
        self.load_patterns()
        print(f"[LEARNER] Self Learner initialized "
              f"({len(self.patterns)} patterns loaded)")

    def load_patterns(self):
        rows = get_all_patterns()
        self.patterns = []
        for row in rows:
            self.patterns.append({
                "id":          row[0],
                "attack_type": row[1],
                "ports":       json.loads(row[2]),
                "timing":      json.loads(row[3]),
                "score":       row[4]
            })

    def learn(self, fingerprint, attack_type="UNKNOWN"):
        save_pattern(
            attack_type,
            fingerprint.get("ports", []),
            {"rate": fingerprint.get("request_rate", 0)},
            fingerprint.get("syn_count", 0)
        )
        self.load_patterns()
        print(f"[LEARNER] New pattern learned: {attack_type}")
        print(f"[LEARNER] Total patterns: {len(self.patterns)}")

    def is_known_attack(self, fingerprint):
        current_ports = set(fingerprint.get("ports", []))
        if not current_ports:
            return False, None
        for pattern in self.patterns:
            known_ports = set(pattern["ports"])
            if not known_ports:
                continue
            overlap = len(current_ports & known_ports)
            match   = overlap / len(known_ports)
            if match >= 0.70:
                print(f"[LEARNER] Known attack matched: "
                      f"{pattern['attack_type']} "
                      f"({match*100:.0f}% match)")
                return True, pattern["attack_type"]
        return False, None

    def get_stats(self):
        return {
            "total_patterns": len(self.patterns),
            "types": list(set(
                p["attack_type"] for p in self.patterns
            ))
        }