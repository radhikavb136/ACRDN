# ─────────────────────────────────────
# ACRDN - Raspberry Pi 4 Controller
# Runs ON Raspberry Pi via RealVNC
# Command: python3 pi_controller.py
# ─────────────────────────────────────

from flask import Flask, request, jsonify
import RPi.GPIO as GPIO
import threading
import time

app = Flask(__name__)

# GPIO Pin Setup
GREEN_LED  = 17
YELLOW_LED = 27
RED_LED    = 22
BUZZER     = 23

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(GREEN_LED,  GPIO.OUT)
GPIO.setup(YELLOW_LED, GPIO.OUT)
GPIO.setup(RED_LED,    GPIO.OUT)
GPIO.setup(BUZZER,     GPIO.OUT)

current_state = "NORMAL"
reset_timer   = None

def clear_all():
    GPIO.output(GREEN_LED,  GPIO.LOW)
    GPIO.output(YELLOW_LED, GPIO.LOW)
    GPIO.output(RED_LED,    GPIO.LOW)
    GPIO.output(BUZZER,     GPIO.LOW)

def set_normal():
    global current_state
    current_state = "NORMAL"
    clear_all()
    GPIO.output(GREEN_LED, GPIO.HIGH)
    print("[PI] GREEN - Normal")

def set_suspicious():
    global current_state, reset_timer
    current_state = "SUSPICIOUS"
    clear_all()
    GPIO.output(YELLOW_LED, GPIO.HIGH)
    print("[PI] YELLOW - Suspicious")
    schedule_reset(20)

def set_malicious():
    global current_state, reset_timer
    current_state = "MALICIOUS"
    cancel_reset()
    clear_all()
    GPIO.output(RED_LED, GPIO.HIGH)
    for _ in range(3):
        GPIO.output(BUZZER, GPIO.HIGH)
        time.sleep(0.3)
        GPIO.output(BUZZER, GPIO.LOW)
        time.sleep(0.2)
    print("[PI] RED + BUZZER - ATTACK!")
    schedule_reset(30)

def schedule_reset(seconds):
    global reset_timer
    cancel_reset()
    reset_timer = threading.Timer(seconds, set_normal)
    reset_timer.daemon = True
    reset_timer.start()

def cancel_reset():
    global reset_timer
    if reset_timer is not None:
        reset_timer.cancel()
        reset_timer = None

@app.route("/alert", methods=["POST"])
def alert():
    data   = request.json
    intent = data.get("attack_type", "NORMAL")
    ip     = data.get("attacker_ip", "unknown")
    print(f"[PI] Alert: {intent} from {ip}")
    if "MALICIOUS" in intent or "ATTACK" in intent:
        threading.Thread(
            target=set_malicious, daemon=True
        ).start()
    elif "SUSPICIOUS" in intent:
        if current_state != "MALICIOUS":
            threading.Thread(
                target=set_suspicious, daemon=True
            ).start()
    else:
        if current_state == "NORMAL":
            threading.Thread(
                target=set_normal, daemon=True
            ).start()
    return jsonify({
        "status": "ok",
        "current_state": current_state
    })

@app.route("/reset", methods=["POST"])
def reset():
    cancel_reset()
    set_normal()
    return jsonify({"status": "reset"})

@app.route("/test")
def test():
    threading.Thread(
        target=set_malicious, daemon=True
    ).start()
    return jsonify({"status": "test triggered"})

@app.route("/ping")
def ping():
    return jsonify({
        "status": "alive",
        "current_state": current_state
    })

if __name__ == "__main__":
    print("[PI] ACRDN Hardware Panel Starting...")
    print("[PI] Listening on port 9000")
    set_normal()
    try:
        app.run(
            host="0.0.0.0",
            port=9000,
            debug=False
        )
    finally:
        cancel_reset()
        GPIO.cleanup()