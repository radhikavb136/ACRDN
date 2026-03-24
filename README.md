ACRDN — Adaptive Cognitive Routing and Deception Network

A unified intelligent network security system that combines smart routing, behavioral threat detection, deception security, self-learning, and offline resilience into one platform — with real hardware integration via Raspberry Pi 4.

![WhatsApp Image 2026-03-20 at 11 01 28 (1)](https://github.com/user-attachments/assets/e6e7448c-87ae-4d7c-962d-8c3c020cc849)
![WhatsApp Image 2026-03-20 at 11 01 29](https://github.com/user-attachments/assets/4e08e915-2f19-44a5-8ae3-e3406c02757a)
![WhatsApp Image 2026-03-20 at 12 35 05](https://github.com/user-attachments/assets/c3884e60-8bf6-4238-ac46-1352aca8ce76)
![WhatsApp Image 2026-03-20 at 12 35 06](https://github.com/user-attachments/assets/b1e36ccc-9186-4da6-a466-6888ed0d8d07)

📌 What is ACRDN?
Most network security systems solve one problem at a time:

Routers only do routing
Firewalls only block threats
Honeypots are deployed separately
Nothing talks to each other

ACRDN solves all of this in one unified engine.
When a packet arrives, ACRDN simultaneously:

Picks the fastest routing path based on real-time load
Scores the sender's behavior to detect intent
Applies a three-tier adaptive response based on that intent
Learns from every attack to detect it faster next time
Works even when the internet is offline
Lights up physical LEDs on Raspberry Pi to show status


🎯 The 5 Core Features
 Feature 1 — Smart Cognitive Routing
Traditional routing picks the shortest path by hop count.
ACRDN picks the fastest path using a real-time cost formula:
              Cost = (Load × 0.4) + (Latency × 0.6)
Network graph built with NetworkX
Edge weights update in real time from live traffic measurements
Dijkstra's algorithm runs on this dynamic graph
Load decays automatically every 5 seconds
Path switches live when congestion is detected

Example:
Path A→B→D→E  →  B is 80% loaded  →  Cost: HIGH
Path A→C→D→E  →  C is 5% loaded   →  Cost: LOW
System picks A→C→D→E even though it has more hops


🔍 Feature 2 — Behavioral Intent Classification
No signature files. No static rules. Pure behavior analysis.
Every IP gets a real-time threat score:
BehaviorPoints2+ unique ports scanned+105+ unique ports scanned+15 more15+ unique ports scanned+25 more30+ unique ports scanned+35 more10+ SYN packets (no handshake)+2050+ SYN packets+35 moreRequest rate > 2/sec+10Request rate > 10/sec+20 moreRequest rate > 30/sec+30 moreData volume > 500KB+10
Score thresholds:

0 – 15 → 🟢 NORMAL → Best path routing
15 – 60 → 🟡 SUSPICIOUS → Monitored path + delay
60+ → 🔴 MALICIOUS → Honeypot redirect


🎭 Feature 3 — Adaptive Three-Tier Response
The routing decision IS the security decision. One unified engine.
🟢 Normal Traffic

Routes via optimal Dijkstra path
Zero interference
Full speed delivery

🟡 Suspicious Traffic

Routes via monitored secondary path
+50ms artificial delay added silently
Every packet logged
Yellow LED lights on Raspberry Pi
Attacker has no idea they are being watched

🔴 Malicious Traffic

NOT blocked (blocking tells attacker they were caught)
Transparently redirected to Honeypot server
Attacker sees fake admin portal, fake files, fake users
Every move they make is secretly logged
Real system completely untouched
Red LED + Buzzer triggers on Raspberry Pi
Push notification sent to admin phone instantly

Honeypot endpoints:
URLWhat Attacker Sees/Fake corporate admin portal/filesFake sensitive file listing/usersFake admin user accounts/configFake server configuration/loginAlways returns success (logs credentials)

🧠 Feature 4 — Self-Learning Engine
ACRDN gets smarter after every attack. No human intervention needed.
How it works:

After a confirmed attack session, system extracts a behavioral fingerprint:

Ports accessed (in sequence)
Total SYN count
Average request rate
Session duration
Total bytes transferred


Fingerprint saved to SQLite database (acrdn_brain.db)
Next time any IP shows similar behavior:

Compare using Jaccard similarity on port sets
If similarity ≥ 70% → Instant MALICIOUS (no scoring needed)
Detection happens in first 2-3 packets


System never forgets — patterns persist across restarts

Day 1   → 0 patterns, learns from scratch
Day 5   → 3 attacks learned, instant recognition
Day 30  → 20+ patterns, most attacks caught immediately

📴 Feature 5 — Offline Detection & Resilience
Most cloud security systems fail when internet goes down.
ACRDN keeps working.
Online mode:

Firebase Cloud Messaging (global push notifications)
ntfy cloud service (any network)

Offline mode:

Scapy still captures all local packets ✅
Intent classifier still scores behavior ✅
Honeypot still redirects attackers ✅
Raspberry Pi still gets alert via LAN ✅
Phone gets alert via same WiFi (ntfy local) ✅
All attacks logged to offline_attacks table ✅

When internet restores:

System detects reconnection automatically
All pending alerts sent to phone immediately
Nothing missed, complete audit trail


🍓 Hardware Integration — Raspberry Pi 4
Physical security panel with visual and audio indicators.
GPIO Wiring
Raspberry Pi 4
├── GPIO 17 (Pin 11) → 220Ω → GREEN LED  → GND
├── GPIO 27 (Pin 13) → 220Ω → YELLOW LED → GND
├── GPIO 22 (Pin 15) → 220Ω → RED LED    → GND
├── GPIO 23 (Pin 16) ──────── BUZZER (+) → GND
└── Pin 6 (GND) ─────────── All negatives
LED Behavior
LEDWhenMeaning🟢 GreenAlways onSystem normal, monitoring active🟡 YellowSuspicious detectedSomeone scanning slowly🔴 RedAttack confirmedMalicious behavior, honeypot active🔊 BuzzerWith Red3 beeps — audio alert
Auto-Reset

Yellow LED auto-resets to Green after 20 seconds
Red LED auto-resets to Green after 30 seconds
New attack during Red period extends the timer

RealVNC

Pi runs headlessly (no monitor needed)
Controlled via RealVNC Viewer from any laptop
See Pi terminal and GPIO status remotely


📊 Live Dashboard
Access at: http://localhost:5000
┌─────────────────────────────────────────────────────┐
│  ACRDN Live Dashboard                    ● LIVE     │
├─────────────────┬───────────────┬───────────────────┤
│ Patterns: 12    │ Attacks: 3    │ Honeypot: ACTIVE  │
├─────────────────┴───────────────┴───────────────────┤
│ Current Best Path: A → C → D → E                   │
├─────────────────────────────────────────────────────┤
│ Network Graph — Live Load                           │
│ A→B: 75% CONGESTED  A→C: 5% FREE                  │
├─────────────────────────────────────────────────────┤
│ Active Connections                                  │
│ 192.168.1.20  [MALICIOUS]  85/100  → Honeypot      │
│ 192.168.1.15  [SUSPICIOUS] 35/100  → Monitored     │
│ 192.168.1.10  [NORMAL]     5/100   → Best Path     │
└─────────────────────────────────────────────────────┘

📁 Project Structure
ACRDN/
│
├── main.py                    ← Run this to start everything
├── config.py                  ← All settings and IPs
├── logger.py                  ← CSV result logging
├── acrdn_brain.db             ← SQLite (auto created)
├── acrdn_results.csv          ← Results log for paper
├── hacker_activity.log        ← Honeypot attacker log
│
├── core/
│   ├── routing_engine.py      ← Feature 1: Smart routing
│   ├── intent_classifier.py   ← Feature 2: Behavior scoring
│   ├── adaptive_response.py   ← Feature 3: 3-tier response
│   ├── self_learner.py        ← Feature 4: Pattern learning
│   └── offline_detector.py   ← Feature 5: Offline resilience
│
├── honeypot/
│   └── fake_server.py         ← Fake admin server
│
├── hardware/
│   └── pi_controller.py       ← Runs ON Raspberry Pi
│
├── notifications/
│   ├── firebase_alert.py      ← Firebase push notification
│   └── local_alert.py         ← ntfy local + cloud
│
├── dashboard/
│   └── app.py                 ← Live web dashboard
│
└── database/
    └── db_manager.py          ← SQLite operations

⚙️ Setup Guide
Requirements
Detection Laptop (Windows/Mac/Linux):
bashpip install scapy flask requests networkx scikit-learn flask-socketio eventlet firebase-admin
Windows extra:

Download and install Npcap with WinPcap API mode

Raspberry Pi:
bashpip3 install flask RPi.GPIO requests --break-system-packages
Configuration
Edit config.py with your actual IPs:
pythonDETECTION_IP      = "192.168.x.10"   # Your laptop IP
RASPBERRY_PI_IP   = "192.168.x.30"   # Pi IP
NETWORK_INTERFACE = "Wi-Fi"          # Your interface name
NTFY_TOPIC        = "acrdn-yourname" # Unique topic name
Find your interface name:
bash# Windows
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Linux/Mac
ip a

🚀 Running the System
Step 1 — Start Pi Controller (on Raspberry Pi via RealVNC)
bashpython3 pi_controller.py
Step 2 — Start ACRDN on Detection Laptop
bash# Windows — run as Administrator
python main.py
Step 3 — Open Dashboard
http://localhost:5000
Step 4 — Setup Phone Notifications
1. Install ntfy app (Android / iOS)
2. Subscribe to: https://ntfy.sh/acrdn-yourname
3. You will receive instant alerts on attack
Step 5 — Test Attack (from Attacker Laptop)
bash# Light scan → triggers SUSPICIOUS → Yellow LED
nmap 192.168.x.10 -p 1-50

# Aggressive scan → triggers MALICIOUS → Red LED + Buzzer
nmap -sS 192.168.x.10 -p 1-1000 -T4

🧪 What You Will See
Detection Laptop terminal:
[RESPONSE] SUSPICIOUS  192.168.x.20 → monitored path
[RESPONSE] MALICIOUS   192.168.x.20 → HONEYPOT
[LEARNER]  New pattern learned: PORT_SCAN
[NOTIFY]   Phone notified via ntfy!
[FIREBASE] Sent: projects/acrdn/messages/xxx

Raspberry Pi (via RealVNC):
[PI] YELLOW - Suspicious
[PI] RED + BUZZER - ATTACK!
[PI] Alert received: ATTACK_DETECTED from 192.168.x.20

Phone:
🚨 ACRDN - Attack Detected!
   Attacker IP: 192.168.x.20
   Action: Redirected to honeypot

Attacker browser (192.168.x.10:8888):
   Company Internal Portal — Admin Panel
   Files | Users | Config | Login
   (All fake — attacker thinks they're inside)

📈 Results Logging
Every event is logged to acrdn_results.csv:
timestamp            | src_ip         | intent    | score | ports | syn | path         | ms
---------------------|----------------|-----------|-------|-------|-----|--------------|----
2026-03-17 14:32:01  | 192.168.1.20   | NORMAL    | 5     | 1     | 0   | A→C→D→E     | 0.2
2026-03-17 14:32:15  | 192.168.1.20   | SUSPICIOUS| 25    | 8     | 0   | A→B→E       | 0.3
2026-03-17 14:32:45  | 192.168.1.20   | MALICIOUS | 85    | 35    | 120 | A→HONEYPOT  | 0.8
Open in Excel for paper results table.


📋 Tech Stack
ComponentTechnologyPacket CaptureScapy + NpcapRouting AlgorithmNetworkX + DijkstraWeb DashboardFlask + SSEHoneypot ServerFlaskDatabaseSQLitePush NotificationsFirebase FCM + ntfyHardware ControlRPi.GPIO + FlaskRemote Pi AccessRealVNCPattern MatchingJaccard SimilarityResult LoggingPython CSV

⚠️ Important Notes

Run main.py as Administrator (Scapy needs raw socket access)
All devices must be on the same WiFi network
Pi controller must be running before starting main.py
Never share firebase_creds.json or config.py publicly
Add both to .gitignore before pushing to GitHub


📄 License
This project is proprietary. All rights reserved.
Patent application filed — unauthorized use prohibited.

Built with Python · Scapy · NetworkX · Flask · Firebase · Raspberry Pi
