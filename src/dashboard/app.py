from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import os
import json
import sys
from datetime import datetime
from functools import wraps

# Add src to path to import from client and server
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from client.crypto_utils import sign_data, encrypt_data
from server.security import security_check, reset_ip
from server.crypto_verify import verify_signature

app = Flask(__name__)
app.secret_key = 'some_secret_key'  # For flash messages

# Admin Credentials Management
admin_creds_file = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'admin_creds.json')

def get_admin_password():
    try:
        with open(admin_creds_file, 'r') as f:
            creds = json.load(f)
            return creds.get("password", "ADMIN")
    except (FileNotFoundError, json.JSONDecodeError):
        return "ADMIN"

def set_admin_password(new_password):
    creds = {"password": new_password}
    with open(admin_creds_file, 'w') as f:
        json.dump(creds, f)

# Admin Login Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

whitelist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.txt')
logs_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(logs_dir, exist_ok=True)
blocked_log_file = os.path.join(logs_dir, 'blocked_logs.json')
audit_log_file = os.path.join(logs_dir, 'audit_logs.json')
chat_log_file = os.path.join(logs_dir, 'chat_logs.json')
config_log_file = os.path.join(logs_dir, 'plant_config.json')

PLANT_IP_MAP = {
    "Plant-A": "127.0.0.1",
    "Plant-B": "192.168.1.10",
    "Plant-C": "10.0.0.45",
    "Plant-D": "172.16.0.23",
    "Plant-E": "10.10.10.5",
    "Plant-F": "192.168.2.50",
    "Plant-G": "10.20.30.40",
    "Plant-H": "172.16.1.12",
    "Plant-I": "192.168.3.15",
    "Plant-J": "10.0.1.12",
    "Plant-K": "10.10.20.30",
    "Plant-L": "192.168.4.25",
    "Plant-M": "172.16.2.34",
    "Plant-N": "10.30.40.50",
    "Plant-O": "192.168.5.60",
    "Plant-P": "10.0.2.99",
    "Plant-Q": "172.16.3.77",
    "Plant-R": "192.168.10.100",
    "Plant-S": "10.50.60.70",
    "Plant-T": "172.16.4.88"
}

remove_counts = {}

# --- Helper Functions ---
def get_plant_from_ip(ip):
    for plant, plant_ip in PLANT_IP_MAP.items():
        if plant_ip == ip:
            return plant
    return None

def log_admin_action(ip, action):
    plant = get_plant_from_ip(ip)
    plant_id = plant if plant else f"IP-{ip}"
    status = "ACCEPTED" if action == "added" else "REJECTED"
    reason = f"IP whitelisted by admin ({action})" if action == "added" else f"IP removed from whitelist by admin ({action})"
    log_entry = {
        "plant_id": plant_id,
        "time": datetime.now().strftime("%H:%M"),
        "status": status,
        "reason": reason
    }
    try:
        with open(audit_log_file, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    logs.append(log_entry)
    with open(audit_log_file, 'w') as f:
        json.dump(logs, f)

# --- Routes ---

@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == get_admin_password():
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid Password", "error")
            return redirect(url_for('admin_login'))
    return render_template("login.html")

@app.route("/admin/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_pass = request.form.get("old_password")
        new_pass = request.form.get("new_password")
        confirm_pass = request.form.get("confirm_password")
        
        current_pass = get_admin_password()
        
        if old_pass != current_pass:
            flash("Incorrect Old Password", "error")
            return redirect(url_for('change_password'))
            
        if new_pass != confirm_pass:
            flash("New Passwords do not match", "error")
            return redirect(url_for('change_password'))
            
        if not new_pass:
            flash("Password cannot be empty", "error")
            return redirect(url_for('change_password'))
            
        set_admin_password(new_pass)
        flash("Password changed successfully!", "success")
        return redirect(url_for('change_password'))
        
    return render_template("change_password.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    return render_template("index.html")

# --- Config Management ---
@app.route("/admin/config")
@login_required
def config_page():
    try:
        with open(config_log_file, 'r') as f:
            configs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        configs = {}
    try:
        with open(whitelist_path, 'r') as f:
            whitelist_ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        whitelist_ips = []
    return render_template("config.html", configs=configs, plant_ips=PLANT_IP_MAP, whitelist_ips=whitelist_ips)

@app.route("/api/config/save", methods=["POST"])
@login_required
def save_config():
    # Support both JSON and Form data
    if request.is_json:
        data = request.json
        plant_id = data.get("plant_id")
        assign_enc = data.get("assign_encryption")
        assign_sign = data.get("assign_sign")
    else:
        plant_id = request.form.get("plant_id")
        assign_enc = request.form.get("assign_encryption") == "on"
        assign_sign = request.form.get("assign_sign") == "on"
    
    if not plant_id:
        if request.is_json:
            return jsonify({"status": "error", "message": "Please select a plant."}), 400
        flash("Please select a plant.", "error")
        return redirect(url_for('config_page'))
        
    try:
        with open(config_log_file, 'r') as f:
            configs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        configs = {}
        
    configs[plant_id] = {
        "encryption": assign_enc,
        "signature": assign_sign
    }
    
    with open(config_log_file, 'w') as f:
        json.dump(configs, f)
        
    if request.is_json:
        return jsonify({"status": "success", "message": f"Configuration saved for {plant_id}"})
        
    flash(f"Configuration saved for {plant_id}", "success")
    return redirect(url_for('config_page'))

# --- Blocked IPs Management ---
@app.route("/admin/blocked_ips")
@login_required
def blocked_ips_page():
    try:
        with open(blocked_log_file, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    return render_template("blocked_ips.html", logs=logs)

@app.route("/admin/unblock", methods=["POST"])
@login_required
def unblock_ip():
    ip = request.form.get("ip")
    if ip:
        # 1. Reset security state (memory)
        reset_ip(ip)
        
        # 2. Update blocked_logs.json (optional: remove entry or mark resolved)
        # Here we will remove ALL entries for this IP from the blocked log to "clear" it
        try:
            with open(blocked_log_file, 'r') as f:
                logs = json.load(f)
            
            # Keep logs that are NOT this IP
            new_logs = [entry for entry in logs if entry.get("ip") != ip]
            
            with open(blocked_log_file, 'w') as f:
                json.dump(new_logs, f)
                
            flash(f"IP {ip} has been Unblocked and removed from logs.", "success")
        except Exception as e:
            flash(f"Error unblocking IP: {str(e)}", "error")
            
    return redirect(url_for('blocked_ips_page'))

@app.route("/admin/accept_block", methods=["POST"])
@login_required
def accept_block():
    """Whitelists the IP and Unblocks it"""
    ip = request.form.get("ip")
    if ip:
        # 1. Add to Whitelist
        try:
            with open(whitelist_path, 'r') as f:
                current = set(line.strip() for line in f if line.strip())
            
            if ip not in current:
                with open(whitelist_path, 'a') as f:
                    f.write(ip + '\n')
                log_admin_action(ip, "added")
                
                # 2. Unblock (Reset security & Remove from blocked logs)
                reset_ip(ip)
                with open(blocked_log_file, 'r') as f:
                    logs = json.load(f)
                new_logs = [entry for entry in logs if entry.get("ip") != ip]
                with open(blocked_log_file, 'w') as f:
                    json.dump(new_logs, f)
                    
                flash(f"IP {ip} Accepted (Whitelisted) and Unblocked.", "success")
            else:
                flash(f"IP {ip} is already whitelisted.", "error")
                
        except Exception as e:
            flash(f"Error accepting IP: {str(e)}", "error")
            
    return redirect(url_for('blocked_ips_page'))

# --- Chat System ---
@app.route("/api/chat/send", methods=["POST"])
def send_chat():
    data = request.json
    plant_id = data.get("plant_id")
    sender = data.get("sender") # 'user' or 'admin'
    message = data.get("message")
    
    if not plant_id or not message:
        return jsonify({"status": "error", "message": "Missing data"}), 400
        
    try:
        with open(chat_log_file, 'r') as f:
            chats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        chats = {}
        
    if plant_id not in chats:
        chats[plant_id] = []
        
    chat_entry = {
        "sender": sender,
        "message": message,
        "time": datetime.now().strftime("%I:%M %p"),
        "status": "sent" if sender == "user" else "read" # Admin msgs are 'read' by default (or just sent)
    }
    
    chats[plant_id].append(chat_entry)
    
    with open(chat_log_file, 'w') as f:
        json.dump(chats, f)
        
    return jsonify({"status": "success"})

@app.route("/api/chat/get/<plant_id>")
def get_chat(plant_id):
    try:
        with open(chat_log_file, 'r') as f:
            chats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        chats = {}
        
    return jsonify({"chats": chats.get(plant_id, [])})

@app.route("/api/chat/read/<plant_id>", methods=["POST"])
@login_required
def mark_chat_read(plant_id):
    try:
        with open(chat_log_file, 'r') as f:
            chats = json.load(f)
            
        if plant_id in chats:
            updated = False
            for msg in chats[plant_id]:
                if msg["sender"] == "user" and msg.get("status") != "read":
                    msg["status"] = "read"
                    updated = True
            
            if updated:
                with open(chat_log_file, 'w') as f:
                    json.dump(chats, f)
                    
        return jsonify({"status": "success"})
    except:
        return jsonify({"status": "error"})

@app.route("/api/chat/all")
@login_required
def get_all_chats():
    try:
        with open(chat_log_file, 'r') as f:
            chats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        chats = {}
        
    total_unread = 0
    unread_counts = {}
    
    for plant, messages in chats.items():
        count = sum(1 for m in messages if m["sender"] == "user" and m.get("status") != "read")
        unread_counts[plant] = count
        total_unread += count
            
    return jsonify({
        "chats": chats, 
        "unread_counts": unread_counts,
        "total_unread": total_unread
    })


@app.route("/addwhitelist", methods=["GET", "POST"])
@login_required
def add_whitelist():
    if request.method == "POST":
        input_val = request.form.get("ip")
        if input_val:
            # Resolve Plant Name to IP if possible
            if input_val in PLANT_IP_MAP:
                ip = PLANT_IP_MAP[input_val]
                msg_prefix = f"{input_val} ({ip})"
            else:
                ip = input_val
                msg_prefix = f"IP {ip}"

            try:
                # Load current whitelist
                with open(whitelist_path, 'r') as f:
                    current = set(line.strip() for line in f if line.strip())
                if ip in current:
                    flash(f"{msg_prefix} is already in whitelist.", "error")
                else:
                    with open(whitelist_path, 'a') as f:
                        f.write(ip + '\n')
                    flash(f"{msg_prefix} added to whitelist.", "success")
                    log_admin_action(ip, "added")
            except Exception as e:
                flash(f"Error adding {msg_prefix}: {str(e)}", "error")
        return redirect(url_for('add_whitelist'))
    return render_template("addwhitelist.html")

@app.route("/removewhitelist", methods=["GET", "POST"])
@login_required
def remove_whitelist():
    if request.method == "POST":
        input_val = request.form.get("ip")
        if input_val:
            # Resolve Plant Name to IP if possible
            if input_val in PLANT_IP_MAP:
                ip = PLANT_IP_MAP[input_val]
                msg_prefix = f"{input_val} ({ip})"
            else:
                ip = input_val
                msg_prefix = f"IP {ip}"

            remove_counts[ip] = remove_counts.get(ip, 0) + 1
            if remove_counts[ip] >= 3:
                plant = get_plant_from_ip(ip)
                plant_id = plant if plant else f"IP-{ip}"
                blocked_entry = {
                    "plant_id": plant_id,
                    "ip": ip,
                    "reason": "Blocked after 3 admin rejections",
                    "time": datetime.now().strftime("%H:%M")
                }
                try:
                    with open(blocked_log_file, 'r') as f:
                        blocked = json.load(f)
                except FileNotFoundError:
                    blocked = []
                blocked.append(blocked_entry)
                with open(blocked_log_file, 'w') as f:
                    json.dump(blocked, f)
                flash(f"{msg_prefix} blocked after 3 rejections.", "error")
            else:
                try:
                    with open(whitelist_path, 'r') as f:
                        lines = f.readlines()
                    current = [line.strip() for line in lines if line.strip()]
                    if ip not in current:
                        flash(f"{msg_prefix} not found in whitelist.", "error")
                    else:
                        with open(whitelist_path, 'w') as f:
                            for line in lines:
                                if line.strip() != ip:
                                    f.write(line)
                        flash(f"{msg_prefix} removed from whitelist.", "success")
                        log_admin_action(ip, "removed")
                except Exception as e:
                    flash(f"Error removing {msg_prefix}: {str(e)}", "error")
        return redirect(url_for('remove_whitelist'))
    return render_template("removewhitelist.html")

# New routes for logs
@app.route("/api/audit_logs")
def get_audit_logs():
    try:
        with open(audit_log_file, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    # Return logs in reverse order (newest first)
    return jsonify(logs[::-1])

@app.route("/api/blocked_logs")
def get_blocked_logs():
    try:
        with open(blocked_log_file, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    return jsonify(logs)

def log_simulation_result(plant_id, ip, status, reason):
    log_entry = {
        "plant_id": plant_id,
        "ip": ip,
        "time": datetime.now().strftime("%H:%M"),
        "status": status,
        "reason": reason
    }
    
    # Audit Logs
    try:
        with open(audit_log_file, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    logs.append(log_entry)
    with open(audit_log_file, 'w') as f:
        json.dump(logs, f)

    # Blocked Logs (if rejected due to security/rate limit)
    if status == "REJECTED" or status == "BLOCKED":
        blocked_entry = {
            "plant_id": plant_id,
            "ip": ip,
            "reason": reason,
            "time": datetime.now().strftime("%H:%M")
        }
        try:
            with open(blocked_log_file, 'r') as f:
                blocked = json.load(f)
        except FileNotFoundError:
            blocked = []
        blocked.append(blocked_entry)
        with open(blocked_log_file, 'w') as f:
            json.dump(blocked, f)

@app.route("/user")
def user_panel():
    return render_template("user_panel.html")

@app.route("/simulate_send", methods=["POST"])
def simulate_send():
    data = request.json
    plant_id = data.get("plant_id")
    payload_text = data.get("payload")
    priority = data.get("priority", "non-critical")
    
    # 1. Simulate IP
    simulated_ip = PLANT_IP_MAP.get(plant_id, "127.0.0.1")
    
    logs = []
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Initiating transmission from {plant_id} ({simulated_ip})...")
    
    # 2. Client Side: Sign & Encrypt
    try:
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Signing data with {plant_id} Private Key...")
        signature = sign_data(payload_text, plant_id)
        
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Encrypting payload (AES-256-GCM)...")
        encrypted_data = encrypt_data(payload_text, plant_id)
        
        # Construct transmission payload
        transmission = {
            "plant_id": plant_id,
            "data": encrypted_data,
            "signature": signature,
            "priority": priority
        }
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Transmission package ready. Sending to Server...")
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Client-side error: {str(e)}", "logs": logs})

    # 3. Server Side: Security Checks
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Server received request. Performing Security Checks...")
    
    # Check if context needed, but security_check logic uses 'request' for rate limiting store
    # Since we are mocking, we must ensure 'security_check' uses the simulated IP for checks
    
    check_result = security_check(plant_id, priority, ip=simulated_ip)
    
    if check_result:
        # Check failed
        if isinstance(check_result, tuple):
            resp, code = check_result
            err_data = resp.get_json()
        else:
            err_data = check_result.get_json()
            
        error_msg = err_data.get('error', 'Unknown security error')
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Security Check FAILED: {error_msg}")
        
        log_simulation_result(plant_id, simulated_ip, "REJECTED", error_msg)
        return jsonify({"status": "error", "message": error_msg, "logs": logs})
        
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ IP Whitelist & Rate Limit Checks PASSED.")
    
    # 4. Server Side: Verification
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Verifying Digital Signature & Decrypting...")
    
    if verify_signature(transmission):
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Signature VERIFIED. Data Integrity Confirmed.")
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Decryption Successful. Data stored.")
        
        log_simulation_result(plant_id, simulated_ip, "ACCEPTED", "Valid Signature & Whitelisted")
        return jsonify({"status": "success", "logs": logs})
    else:
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Signature Verification FAILED or Data Tampered.")
        log_simulation_result(plant_id, simulated_ip, "REJECTED", "Invalid Signature")
        return jsonify({"status": "error", "message": "Signature Verification Failed", "logs": logs})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
