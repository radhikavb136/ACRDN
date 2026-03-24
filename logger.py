import csv
import os
from datetime import datetime

LOG_FILE = "acrdn_results.csv"

def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "src_ip",
                "intent",
                "score",
                "ports_scanned",
                "syn_count",
                "action_taken",
                "path_used",
                "response_time_ms"
            ])
        print("[LOG] Results logger initialized")
    else:
        print("[LOG] Logger ready")

def log_event(src_ip, intent, score,
              ports, syn_count,
              action, path, response_ms):
    try:
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                src_ip,
                intent,
                score,
                ports,
                syn_count,
                action,
                " -> ".join(path),
                response_ms
            ])
    except Exception as e:
        print(f"[LOG] Error: {e}")