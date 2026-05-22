from flask import Flask, request, jsonify
from security import security_check
from crypto_verify import verify_signature
from audit import log_audit
from datetime import datetime
from collections import defaultdict
import requests
import json
import os

app = Flask(__name__)

PLANT_IP_MAP = {
    "Plant-A": "127.0.0.1",
    "Plant-B": "192.168.1.10",
    "Plant-C": "10.0.0.45",
    "Plant-D": "172.16.0.23",
    "Plant-E": "10.10.10.5",
    "Plant-F": "192.168.2.50",
    "Plant-G": "10.20.30.40"
}

PLANT_COUNTRY = {
    "Plant-A": "US",
    "Plant-B": "IN",
    "Plant-C": "UK"
}

audit_logs = []
blocked_logs = []
failed_attempts = defaultdict(int)
MAX_FAILED_ATTEMPTS = 5

logs_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(logs_dir, exist_ok=True)
audit_log_file = os.path.join(logs_dir, 'audit_logs.json')
blocked_log_file = os.path.join(logs_dir, 'blocked_logs.json')

def save_logs():
    with open(audit_log_file, 'w') as f:
        json.dump(audit_logs, f)
    with open(blocked_log_file, 'w') as f:
        json.dump(blocked_logs, f)

def load_logs():
    global audit_logs, blocked_logs
    try:
        with open(audit_log_file, 'r') as f:
            audit_logs = json.load(f)
    except FileNotFoundError:
        audit_logs = []
    try:
        with open(blocked_log_file, 'r') as f:
            blocked_logs = json.load(f)
    except FileNotFoundError:
        blocked_logs = []

load_logs()  # Load on startup

def get_ip_country(ip):
    try:
        response = requests.get(f'http://ipapi.co/{ip}/country/', timeout=5)
        return response.text.strip() if response.status_code == 200 else None
    except:
        return None

@app.route("/")
def home():
    return "secure server running"

@app.route("/receive-data", methods=["POST"])
def receive_data():
    payload = request.json
    ip = request.remote_addr

    # Check failed attempts
    if failed_attempts[ip] >= MAX_FAILED_ATTEMPTS:
        blocked_logs.append({"plant_id": "Unknown", "ip": ip, "reason": "Too many failed attempts", "time": datetime.now().strftime("%H:%M")})
        save_logs()
        return jsonify({"error": "Too many failed attempts"}), 403

    if not payload:
        failed_attempts[ip] += 1
        blocked_logs.append({"plant_id": "Unknown", "ip": ip, "reason": "Missing payload", "time": datetime.now().strftime("%H:%M")})
        save_logs()
        return jsonify({"error": "Empty payload"}), 400

    plant_id = payload.get("plant_id")
    priority = payload.get("priority", "non-critical")  # Default to non-critical
    if not plant_id:
        failed_attempts[ip] += 1
        blocked_logs.append({"plant_id": "Unknown", "ip": ip, "reason": "Missing plant_id", "time": datetime.now().strftime("%H:%M")})
        save_logs()
        return jsonify({"error": "Missing plant_id"}), 400

    expected_ip = PLANT_IP_MAP.get(plant_id)
    if plant_id in PLANT_IP_MAP and request.remote_addr != expected_ip:
        failed_attempts[ip] += 1
        blocked_logs.append({"plant_id": plant_id, "ip": ip, "reason": "IP not associated with plant", "time": datetime.now().strftime("%H:%M")})
        save_logs()
        return jsonify({"error": "IP not associated with plant"}), 403

    # Geolocation validation (optional flag)
    country = get_ip_country(ip)
    expected_country = PLANT_COUNTRY.get(plant_id)
    if country and expected_country and country != expected_country:
        print(f"Warning: IP {ip} country {country} does not match plant {plant_id} country {expected_country}")

    # 🔐 SECURITY LAYER
    sec = security_check(plant_id, priority)
    if sec:
        failed_attempts[ip] += 1
        blocked_logs.append({"plant_id": plant_id, "ip": ip, "reason": sec[0].get_json()["error"], "time": datetime.now().strftime("%H:%M")})
        save_logs()
        return sec

    # 🔑 VERIFY SIGNATURE
    if not verify_signature(payload):
        failed_attempts[ip] += 1
        audit_logs.append({"plant_id": plant_id, "ip": ip, "time": datetime.now().strftime("%H:%M"), "status": "REJECTED", "reason": "Signature mismatch"})
        log_audit("FAILED", payload)
        save_logs()
        return jsonify({"error": "Signature verification failed"}), 400

    # Reset failed attempts on success
    failed_attempts[ip] = 0

    # 🧾 AUDIT LOG
    audit_logs.append({"plant_id": plant_id, "ip": ip, "time": datetime.now().strftime("%H:%M"), "status": "ACCEPTED", "reason": "Valid data"})
    log_audit("SUCCESS", payload)
    save_logs()
    return jsonify({"status": "received"}), 200

if __name__ == "__main__":
    app.run()
