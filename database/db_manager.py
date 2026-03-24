import sqlite3
import json
from datetime import datetime

DB_PATH = "acrdn_brain.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT,
            dst_port    INTEGER,
            protocol    TEXT,
            intent      TEXT,
            timestamp   TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS learned_patterns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT,
            ports       TEXT,
            timing      TEXT,
            score       REAL,
            seen_count  INTEGER DEFAULT 1,
            created_at  TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS route_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            path        TEXT,
            cost        REAL,
            intent      TEXT,
            timestamp   TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS offline_attacks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT,
            attack_type TEXT,
            details     TEXT,
            notified    INTEGER DEFAULT 0,
            timestamp   TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully")


def log_traffic(src_ip, dst_port, protocol, intent):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO traffic_log
        (src_ip, dst_port, protocol, intent, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (src_ip, dst_port, protocol,
          intent, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def save_pattern(attack_type, ports, timing, score):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO learned_patterns
        (attack_type, ports, timing, score, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (attack_type,
          json.dumps(ports),
          json.dumps(timing),
          score,
          datetime.now().isoformat()))
    conn.commit()
    conn.close()
    print(f"[DB] New pattern saved: {attack_type}")


def get_all_patterns():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT * FROM learned_patterns"
    ).fetchall()
    conn.close()
    return rows


def save_route(path, cost, intent):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO route_history
        (path, cost, intent, timestamp)
        VALUES (?, ?, ?, ?)
    """, (str(path), cost,
          intent, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def save_offline_attack(src_ip, attack_type, details):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO offline_attacks
        (src_ip, attack_type, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (src_ip, attack_type,
          json.dumps(details),
          datetime.now().isoformat()))
    conn.commit()
    conn.close()
    print(f"[DB] Offline attack logged: {src_ip}")


def get_pending_notifications():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT * FROM offline_attacks
        WHERE notified = 0
    """).fetchall()
    conn.close()
    return rows


def mark_notified(attack_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        UPDATE offline_attacks
        SET notified = 1
        WHERE id = ?
    """, (attack_id,))
    conn.commit()
    conn.close()


def get_recent_traffic(limit=20):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT src_ip, dst_port, intent, timestamp
        FROM traffic_log
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def get_stats():
    conn = sqlite3.connect(DB_PATH)

    total_traffic = conn.execute(
        "SELECT COUNT(*) FROM traffic_log"
    ).fetchone()[0]

    total_attacks = conn.execute(
        "SELECT COUNT(*) FROM traffic_log WHERE intent = 'MALICIOUS'"
    ).fetchone()[0]

    total_patterns = conn.execute(
        "SELECT COUNT(*) FROM learned_patterns"
    ).fetchone()[0]

    pending_alerts = conn.execute(
        "SELECT COUNT(*) FROM offline_attacks WHERE notified = 0"
    ).fetchone()[0]

    conn.close()

    return {
        "total_traffic":  total_traffic,
        "total_attacks":  total_attacks,
        "total_patterns": total_patterns,
        "pending_alerts": pending_alerts
    }