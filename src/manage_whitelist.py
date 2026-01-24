import argparse
import os
import json
from datetime import datetime

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
WHITELIST_PATH = os.path.join(PROJECT_ROOT, 'whitelist.txt')
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
AUDIT_LOG_FILE = os.path.join(LOGS_DIR, 'audit_logs.json')

# Same map as in server/app.py
PLANT_IP_MAP = {
    "Plant-A": "127.0.0.1",
    "Plant-B": "192.168.1.10",
    "Plant-C": "10.0.0.45",
    "Plant-D": "172.16.0.23",
    "Plant-E": "10.10.10.5",
    "Plant-F": "192.168.2.50",
    "Plant-G": "10.20.30.40"
}

def get_plant_from_ip(ip):
    for plant, plant_ip in PLANT_IP_MAP.items():
        if plant_ip == ip:
            return plant
    return None

def log_action(ip, action):
    os.makedirs(LOGS_DIR, exist_ok=True)
    plant = get_plant_from_ip(ip)
    plant_id = plant if plant else f"IP-{ip}"
    
    # Dashboard conventions:
    # Adding: status="ACCEPTED", reason="IP whitelisted by admin"
    # Removing: status="REJECTED", reason="IP removed from whitelist by admin"
    
    if action == "added":
        status = "ACCEPTED"
        reason = f"IP whitelisted by CLI"
    else:
        status = "REJECTED"
        reason = f"IP removed from whitelist by CLI"
    
    log_entry = {
        "plant_id": plant_id,
        "time": datetime.now().strftime("%H:%M"),
        "status": status,
        "reason": reason
    }
    
    try:
        with open(AUDIT_LOG_FILE, 'r') as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
        
    logs.append(log_entry)
    
    with open(AUDIT_LOG_FILE, 'w') as f:
        json.dump(logs, f)

def load_whitelist():
    if not os.path.exists(WHITELIST_PATH):
        return set()
    with open(WHITELIST_PATH, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_whitelist(whitelist_set):
    with open(WHITELIST_PATH, 'w') as f:
        for ip in whitelist_set:
            f.write(f"{ip}\n")

def check_ip(ip):
    whitelist = load_whitelist()
    plant = get_plant_from_ip(ip)
    associated_msg = f" (Associated with {plant})" if plant else ""
    
    if ip in whitelist:
        print(f"✅ IP {ip} is currently WHITELISTED{associated_msg}.")
        return True
    else:
        print(f"❌ IP {ip} is NOT whitelisted{associated_msg}.")
        return False

def add_ip(ip):
    whitelist = load_whitelist()
    if ip in whitelist:
        print(f"⚠️  IP {ip} is already in the whitelist.")
        return
    
    whitelist.add(ip)
    save_whitelist(whitelist)
    log_action(ip, "added")
    print(f"✅ IP {ip} has been ADDED to the whitelist.")

def remove_ip(ip):
    whitelist = load_whitelist()
    if ip not in whitelist:
        print(f"⚠️  IP {ip} is not in the whitelist.")
        return
    
    whitelist.remove(ip)
    save_whitelist(whitelist)
    log_action(ip, "removed")
    print(f"🗑️  IP {ip} has been REMOVED from the whitelist.")

def main():
    parser = argparse.ArgumentParser(description="Manage SecureSync IP Whitelist")
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check if an IP is whitelisted')
    check_parser.add_argument('ip', help='IP address to check')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add an IP to the whitelist')
    add_parser.add_argument('ip', help='IP address to add')
    
    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove an IP from the whitelist')
    remove_parser.add_argument('ip', help='IP address to remove')
    
    args = parser.parse_args()
    
    if args.command == 'check':
        check_ip(args.ip)
    elif args.command == 'add':
        add_ip(args.ip)
    elif args.command == 'remove':
        remove_ip(args.ip)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
