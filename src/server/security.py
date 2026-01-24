from flask import request, jsonify
import time
from collections import defaultdict
import os
import json

def load_whitelist():
    whitelist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.txt')
    try:
        with open(whitelist_path, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return {"127.0.0.1"}

RATE_LIMITS = {
    "critical": 10,
    "non-critical": 5
}
TIME_WINDOW = 60
BLOCK_TIME = 300

request_log = defaultdict(list)  # ip -> list of timestamps
blocked_ips = {}  # ip -> block_until

def reset_ip(ip):
    """Resets rate limit logs and unblocks the IP."""
    if ip in blocked_ips:
        del blocked_ips[ip]
    if ip in request_log:
        del request_log[ip]
    return True

def security_check(plant_id, priority="non-critical", ip=None):
    WHITELISTED_IPS = load_whitelist()
    if ip is None:
        ip = request.remote_addr
    now = time.time()

    # Temporary block
    if ip in blocked_ips and now < blocked_ips[ip]:
        return jsonify({"error": "IP temporarily blocked", "ip": ip}), 403

    # Whitelist
    if ip not in WHITELISTED_IPS:
        return jsonify({"error": "IP not whitelisted", "ip": ip}), 403
        
    # Check Configuration (Digital Signature Assignment)
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'plant_config.json')
    try:
        with open(config_path, 'r') as f:
            configs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        configs = {}
        
    # Default is not assigned if not in config
    plant_config = configs.get(plant_id, {})
    # If Digital Signature is NOT assigned in config, block access even if whitelisted
    if not plant_config.get("signature", False):
         return jsonify({"error": "Digital Signature NOT assigned for this Plant. Contact Admin.", "ip": ip}), 403

    # Sliding window rate limit per IP
    rate_limit = RATE_LIMITS.get(priority, 100)
    request_log[ip] = [t for t in request_log[ip] if now - t < TIME_WINDOW]

    if len(request_log[ip]) >= rate_limit:
        blocked_ips[ip] = now + BLOCK_TIME
        return jsonify({"error": "Rate limit exceeded", "ip": ip}), 429

    request_log[ip].append(now)
    return None
