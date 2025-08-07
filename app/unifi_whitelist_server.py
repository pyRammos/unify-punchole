from flask import Flask, request, jsonify
import sqlite3
import threading
import requests
import urllib3
import time
import configparser
from datetime import datetime, timedelta

# === CONFIG ===
CONFIG_FILE = 'data/settings.cfg'
DB_FILE = 'data/whitelisted_ips.db'
SYNC_INTERVAL_SECS = 600  # 10 minutes
IP_EXPIRY_HOURS = 24      # Remove IPs older than this

# === Load settings ===
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

UNIFI_CONTROLLER = config.get('unifi', 'controller_url')
USERNAME = config.get('unifi', 'username')
PASSWORD = config.get('unifi', 'password')
SITE = config.get('unifi', 'site')
FIREWALL_GROUP_NAME = config.get('unifi', 'firewall_group_name')
SHARED_SECRET = config.get('unifi', 'shared_secret')

# === Setup ===
app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.verify = False  # Allow self-signed certs

# === DB Setup ===
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelisted_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized.")

# === Check + Save new IP ===
def is_new_ip(device, ip):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 1 FROM whitelisted_ips
        WHERE device_name = ? AND ip_address = ?
    ''', (device, ip))
    exists = cursor.fetchone()
    conn.close()
    return not exists

def save_ip(device, ip):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO whitelisted_ips (device_name, ip_address, created_at)
        VALUES (?, ?, ?)
    ''', (device, ip, now))
    conn.commit()
    conn.close()

# === Get active IPs & clean expired ===
def get_recent_ips():
    cutoff = (datetime.utcnow() - timedelta(hours=IP_EXPIRY_HOURS)).isoformat()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM whitelisted_ips WHERE created_at < ?", (cutoff,))
    conn.commit()
    cursor.execute("SELECT DISTINCT ip_address FROM whitelisted_ips")
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

# === UniFi API ===
def login_unifi():
    url = f"{UNIFI_CONTROLLER}/api/auth/login"
    resp = session.post(url, json={
        "username": USERNAME,
        "password": PASSWORD,
        "remember": True
    })
    if resp.status_code != 200:
        raise Exception(f"Login failed: {resp.status_code} - {resp.text}")
    csrf_token = resp.headers.get("x-csrf-token")
    if not csrf_token:
        raise Exception("CSRF token not found in response")
    session.headers.update({
        "x-csrf-token": csrf_token,
        "Referer": UNIFI_CONTROLLER,
        "Origin": UNIFI_CONTROLLER
    })

def get_firewall_group():
    url = f"{UNIFI_CONTROLLER}/proxy/network/api/s/{SITE}/rest/firewallgroup"
    resp = session.get(url)
    if resp.status_code != 200:
        raise Exception(f"Failed to get groups: {resp.status_code} - {resp.text}")
    for group in resp.json()['data']:
        if group['name'] == FIREWALL_GROUP_NAME:
            return group
    raise Exception(f"Firewall group '{FIREWALL_GROUP_NAME}' not found")

def update_firewall_group(group_id, ip_list):
    url = f"{UNIFI_CONTROLLER}/proxy/network/api/s/{SITE}/rest/firewallgroup/{group_id}"
    resp = session.put(url, json={"group_members": ip_list})
    if resp.status_code != 200:
        raise Exception(f"Failed to update group: {resp.status_code} - {resp.text}")
    print(f"✅ Synced {len(ip_list)} IPs to UniFi at {datetime.utcnow().isoformat()}")

def sync_to_unifi():
    print("🔄 [Sync] Starting sync process...")
    login_unifi()
    active_ips = get_recent_ips()
    print(f"📋 [Sync] Active IPs: {active_ips}")
    group = get_firewall_group()
    current = set(group.get("group_members", []))
    desired = set(active_ips)

    if current != desired:
        print(f"⬆️ [Sync] Updating firewall group with: {desired}")
        update_firewall_group(group['_id'], active_ips)
    else:
        print("ℹ️ [Sync] No changes needed.")

# === Flask Route ===
@app.route('/update_ip', methods=['POST'])
def update_ip():
    import ipaddress

    data = request.get_json()
    device = data.get('device')
    token = data.get('token')

    if not device or token != SHARED_SECRET:
        return jsonify({'status': 'unauthorized'}), 401

    # ✅ Use CF-Connecting-IP if available (Cloudflare), fallback to remote_addr
    ip = request.headers.get("CF-Connecting-IP") or request.remote_addr

    # ✅ Reject if IP is not IPv4
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            print(f"🛑 Ignoring non-IPv4 address: {ip}")
            return jsonify({"status": "ignored", "reason": "IPv6 not supported"}), 400
    except ValueError:
        print(f"⚠️ Invalid IP address received: {ip}")
        return jsonify({"status": "error", "reason": "Invalid IP"}), 400

    # ✅ If it's a new IP, store it and sync
    if is_new_ip(device, ip):
        print(f"➕ New IP detected: {device} → {ip}")
        save_ip(device, ip)
        threading.Thread(target=sync_to_unifi, daemon=True).start()
        return jsonify({'status': 'synced', 'device': device, 'ip': ip})
    else:
        print(f"🔁 IP already exists for {device}: {ip}")
        return jsonify({'status': 'unchanged', 'device': device, 'ip': ip})

# === Background Cleanup + Sync ===
def background_sync():
    print("🚀 [Sync] Background thread started.")
    while True:
        try:
            sync_to_unifi()
        except Exception as e:
            print(f"❌ [Sync] Error: {e}")
        time.sleep(SYNC_INTERVAL_SECS)

# === Main Entrypoint ===
if __name__ == '__main__':
    init_db()
    threading.Thread(target=background_sync, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
