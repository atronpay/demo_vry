import json
from pathlib import Path
from datetime import datetime
import hashlib

DEVICES_FILE = Path("devices.json")

def client_ip():
    """Get real client IP from Flask request headers"""
    from flask import request
    keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR']
    for k in keys:
        ip = request.environ.get(k)
        if ip:
            ip_list = ip.split(',')
            candidate = ip_list[0].strip()
            return candidate
    return request.remote_addr or '0.0.0.0'

def make_fingerprint(ua, ip):
    """Create SHA256 fingerprint from IP + UA"""
    return hashlib.sha256(f"UA:{ua}|IP:{ip}".encode()).hexdigest()

def read_all_devices():
    """Read all devices from persistent storage"""
    if not DEVICES_FILE.exists():
        return []
    with open(DEVICES_FILE, "r") as f:
        return [json.loads(line) for line in f if line.strip()]

def save_user_device(device_record):
    """Save device record to file"""
    with open(DEVICES_FILE, 'a') as f:
        f.write(json.dumps(device_record) + '\n')

# def check_device_match_all(ip, ua):
#     fingerprint = make_fingerprint(ua, ip)
#     if redis_client.sismember("global:devices", fingerprint):
#         # Find user who owns this device
#         for key in redis_client.keys("user:*:devices"):
#             devices = redis_client.lrange(key, 0, -1)
#             for d in devices:
#                 dev = json.loads(d)
#                 if dev['fingerprint'] == fingerprint:
#                     return dev
#     return None
