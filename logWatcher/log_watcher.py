import os
import time
import logging
import requests
import sys
import json
import re
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch, ConnectionError, TransportError
from collections import deque
from dateutil.parser import isoparse

# --- Cấu hình Logger ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger('log-watcher')
logger.setLevel(LOG_LEVEL)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s - [LOG-WATCHER] - [%(levelname)s] - %(message)s'))
    logger.addHandler(handler)
logger.propagate = False
logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

# --- Cấu hình chính (Đã đơn giản hóa) ---
ELK_URL = os.getenv("ELK_URL")
ALERT_ENDPOINT = os.getenv("ALERT_ENDPOINT", "http://alert-api:5001/alert")
CHECK_INTERVAL_SECONDS = 30
COOLDOWN_SECONDS = 900
# [ĐƠN GIẢN HÓA] Hardcode đường dẫn trực tiếp. Không cần biến môi trường nữa.
ARCHIVED_LOGS_DIR = "/app/archived_logs" 

# --- Lấy KEYWORDS ĐỘNG ---
DEFAULT_KEYWORDS = "error,failed,exception,denied,timeout,refused,critical,upstream timed out,connect() failed"
KEYWORDS_STR = os.getenv("LOG_WATCHER_KEYWORDS", DEFAULT_KEYWORDS)
KEYWORDS = [keyword.strip() for keyword in KEYWORDS_STR.split(',') if keyword.strip()]

# ... (Các hàm get_cooldown_cache, update_cooldown_cache, connect_to_es giữ nguyên y hệt) ...
def get_cooldown_cache():
    try:
        with open("/app/log_watcher_cooldown.json", 'r') as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}

def update_cooldown_cache(cache):
    with open("/app/log_watcher_cooldown.json", 'w') as f: json.dump(cache, f)

def connect_to_es():
    if not ELK_URL:
        logger.error("ELK_URL environment variable is not set.")
        return None
    try:
        client = Elasticsearch(ELK_URL, request_timeout=15, max_retries=3)
        if not client.ping():
            raise ConnectionError("Ping to Elasticsearch failed.")
        return client
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        return None

def process_logs(es_client, processed_log_ids):
    # ... (Phần đầu hàm giữ nguyên) ...
    start_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    keyword_query_string = " OR ".join([f'"{k}"' if ' ' in k else k for k in KEYWORDS])
    query = { "bool": { "must": [ {"range": {"@timestamp": {"gte": start_time.isoformat()}}}, {"query_string": { "query": keyword_query_string, "default_field": "message", "analyze_wildcard": True }} ] } }
    logger.debug(f"Executing ES Query: {keyword_query_string}")
    try:
        res = es_client.search(index="filebeat-*", query=query, sort=[{"@timestamp": "desc"}], size=50, ignore_unavailable=True)
    except TransportError as e:
        logger.error(f"Error searching logs on Elasticsearch: {e}")
        return
    if not res['hits']['hits']:
        return
    
    last_alert_time = get_cooldown_cache()
    now_ts = int(time.time())

    for hit in reversed(res['hits']['hits']):
        # ... (Phần logic xử lý hit, cooldown giữ nguyên) ...
        log_id = hit['_id']
        if log_id in processed_log_ids:
            continue
        processed_log_ids.append(log_id)
        source = hit['_source']
        log_message = source.get('message', 'N/A').strip()
        hostname = source.get('host', {}).get('name') or "unknown_host"
        timestamp_str = source.get('@timestamp')
        error_signature = ' '.join(re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[*\d#]+|[:.]', '', log_message).split()[:7])
        cache_key = f"{hostname}:{error_signature}"
        if (now_ts - last_alert_time.get(cache_key, 0)) < COOLDOWN_SECONDS:
            continue
        last_alert_time[cache_key] = now_ts
        update_cooldown_cache(last_alert_time)

        incident_id = f"LOG_{datetime.now().strftime('%H%M%S')}_{hostname.replace('.', '_')}"
        logger.warning(f"✅ DETECTED new error log (Incident: {incident_id}) from '{hostname}': {log_message[:150]}...")

        # [ĐƠN GIẢN HÓA] Lưu log gốc vào file, không cần cấu hình gì thêm
        try:
            today_str = datetime.now().strftime('%Y-%m-%d')
            daily_archive_path = os.path.join(ARCHIVED_LOGS_DIR, today_str)
            os.makedirs(daily_archive_path, exist_ok=True)
            
            log_filepath = os.path.join(daily_archive_path, f"{incident_id}.log")
            with open(log_filepath, 'w', encoding='utf-8') as f:
                f.write(log_message)
            logger.info(f"   -> Archived log to {log_filepath}")
        except Exception as e:
            logger.error(f"   -> Failed to archive log for incident '{incident_id}': {e}")
        
        unix_timestamp = int(isoparse(timestamp_str).timestamp()) if timestamp_str else now_ts
        payload = { "source": "LogWatcher", "metric": "log_error_detected", "instance": hostname, "severity": "warning", "trigger_log": log_message, "timestamp": unix_timestamp }
        
        try:
            requests.post(ALERT_ENDPOINT, json=payload, timeout=60)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send alert for incident '{incident_id}': {e}")


if __name__ == "__main__":
    es_client = None
    processed_log_ids = deque(maxlen=5000)
    logger.info(f"🚀 Log Watcher (v9.5 - Simplified) is starting...")
    logger.info(f"Watching for keywords: {KEYWORDS}")
    # Đảm bảo thư mục chính tồn tại khi khởi động
    os.makedirs(ARCHIVED_LOGS_DIR, exist_ok=True)
    logger.info(f"Archiving detected logs to: {ARCHIVED_LOGS_DIR}")

    while True:
        try:
            if es_client is None or not es_client.ping():
                es_client = connect_to_es()
            if es_client:
                process_logs(es_client, processed_log_ids)
            else:
                time.sleep(30)
        except Exception as e:
            logger.critical(f"Critical error in main loop: {e}", exc_info=True)
            es_client = None
        time.sleep(CHECK_INTERVAL_SECONDS)
