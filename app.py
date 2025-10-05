from flask import Flask, render_template, request, jsonify, redirect, url_for,make_response
import redis
import json
import requests
import logging
from datetime import datetime
import hashlib
import uuid
import config
import os
import hmac
import hashlib
import time
import urllib.parse
from device_utils import client_ip, make_fingerprint, save_user_device

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize Redis client
try:
    redis_client = redis.Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        decode_responses=True,
        username=config.REDIS_USERNAME,
        password=config.REDIS_PASSWORD
    )
    redis_client.ping()
    logger.info("Flask Redis connected successfully")
except Exception as e:
    logger.error(f"Flask Redis connection failed: {e}")
    redis_client = None

def get_user_data(user_id):
    """Get user data from Redis"""
    if not redis_client:
        return None
    try:
        user_data = redis_client.get(f"user:{user_id}")
        if user_data and isinstance(user_data, str):
            return json.loads(user_data)
        return None
    except Exception as e:
        logger.error(f"Error getting user data: {e}")
        return None

def save_user_data(user_id, data):
    """Save user data to Redis"""
    if not redis_client:
        return False
    try:
        redis_client.set(f"user:{user_id}", json.dumps(data))
        return True
    except Exception as e:
        logger.error(f"Error saving user data: {e}")
        return False




def save_user_ip(user_id, ip):
    """Save user IP"""
    if not redis_client:
        return False
    try:
        redis_client.set(f"user_ip:{user_id}", ip)
        return True
    except Exception as e:
        logger.error(f"Error saving user IP: {e}")
        return False

def check_ip_exists(ip, exclude_user=None):
    """Check if IP is already used by another user"""
    if not redis_client:
        return False
    try:
        for key in redis_client.scan_iter(match="user_ip:*"):
            user_id = key.split(":")[1]
            if exclude_user and int(user_id) == exclude_user:
                continue
            stored_ip = redis_client.get(key)
            if stored_ip == ip:
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking IP: {e}")
        return False




def call_data_api(service_key, query):
    """Call data lookup API"""
    try:
        service_config = config.DATA_LOOKUP_APIS.get(service_key)
        if not service_config:
            return None
        
        url = service_config['url']
        params = service_config['params'].copy()
        
        # Update the parameter based on service type
        for param_key, param_value in params.items():
            if param_value == "":
                params[param_key] = query
                break
        
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return f"Error: API returned status {response.status_code}"
    except Exception as e:
        logger.error(f"API call error: {e}")
        return f"❌ No data found"

@app.route('/')
def index():
    """Main mini app page"""
    return render_template('index.html', services=config.SERVICE_NAMES)


def get_device_id():
    """Get or create persistent device_id cookie."""
    device_id = request.cookies.get("device_id")
    if not device_id:
        device_id = str(uuid.uuid4())
    return device_id

def make_fingerprint(user_agent, extra_info=None):
    fp_source = user_agent
    if isinstance(extra_info, dict):
        fp_source += "".join(extra_info.values())
    elif isinstance(extra_info, str):
        fp_source += extra_info
    return hashlib.sha256(fp_source.encode()).hexdigest()

# ------------------ Redis Device Functions ------------------
def get_user_devices(user_id):
    key = f"user:{user_id}:devices"
    devices = redis_client.lrange(key, 0, -1)
    return [json.loads(d) for d in devices] if devices else []

def save_user_device(user_id, device_record):
    fingerprint = device_record['fingerprint']

    # Check all users' devices
    all_users_keys = redis_client.keys("user:*:devices")
    for user_key in all_users_keys:
        uid = user_key.split(":")[1]
        devices = redis_client.lrange(user_key, 0, -1)
        for d_json in devices:
            d = json.loads(d_json)
            if d['fingerprint'] == fingerprint:
                if uid == str(user_id):
                    print(f"[ALREADY VERIFIED] Device for user {user_id}")
                    return "already_verified"
                else:
                    mark_user_failed(user_id, "Device already used by another account")
                    return "failed"

    # New device → save and verify
    redis_client.sadd("global:devices", fingerprint)
    redis_client.rpush(f"user:{user_id}:devices", json.dumps(device_record))
    mark_user_verified(user_id)
    return "verified"

def mark_user_verified(user_id):
    redis_client.set(f"user:{user_id}:verified", "true")
    redis_client.delete(f"user:{user_id}:failed")
    print(f"[VERIFIED] User {user_id}")

def mark_user_failed(user_id, reason):
    redis_client.hset(f"user:{user_id}:failed", mapping={
        "reason": reason,
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    redis_client.delete(f"user:{user_id}:verified")
    print(f"[FAILED] User {user_id}: {reason}")

def get_user_verification_status(user_id):
    if redis_client.exists(f"user:{user_id}:verified"):
        return {"status": "verified"}
    elif redis_client.exists(f"user:{user_id}:failed"):
        fail_data = redis_client.hgetall(f"user:{user_id}:failed")
        return {"status": "failed", "reason": fail_data.get("reason"), "time": fail_data.get("time")}
    else:
        return {"status": "pending"}

# ------------------ Device Verification Route ------------------
@app.route('/device/<user_id>')
def device_verify(user_id):
    ua = request.headers.get('User-Agent', 'unknown')
    device_id = get_device_id()  # use persistent cookie
    fingerprint = make_fingerprint(ua, device_id)
    ip = client_ip()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    device_record = {
        'user_id': user_id,
        'fingerprint': fingerprint,
        'ip': ip,
        'user_agent': ua,
        'device_id': device_id,
        'created_at': now
    }

    status = save_user_device(user_id, device_record)
    verified_info = get_user_verification_status(user_id)
    logger.info(verified_info)
    logger.info(status)

    # Return response with cookie
    resp = make_response(render_template(
        'device_verify.html',
        user_id=user_id,
        verified_info=verified_info,
        device_status=status
    ))
    resp.set_cookie("device_id", device_id, max_age=60*60*24*365)  # 1 year
    return resp



app.tun()
