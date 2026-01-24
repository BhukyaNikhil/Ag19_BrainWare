from datetime import datetime

def log_audit(status, payload):
    print(f"[{datetime.now()}] {status} → {payload}")
