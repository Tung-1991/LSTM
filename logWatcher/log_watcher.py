import os
import time
import logging
import logging.handlers
import requests
import sys
import json
import re
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, ConnectionError, TransportError
from collections import deque

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger('log-watcher')
logger.setLevel(log_level)
if not logger.handlers:
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter('%(asctime)s - [LOG-WATCHER] - %(levelname)s - %(message)s'))
    logger.addHandler(stream_handler)
logger.propagate = False
logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

ELK_URL = os.getenv("ELK_URL")
ALERT_ENDPOINT = os.getenv("ALERT_ENDPOINT", "http://alert-api:5001/alert")
CHECK_INTERVAL_SECONDS = 60
KEYWORDS = ["error", "failed", "exception", "denied", "timeout", "refused", "critical"]
MAX_PROCESSED_LOG_IDS = 5000
ARCHIVE_DIR = "/app/archived_logs"
COOLDOWN_CACHE_FILE = "/app/log_watcher_cooldown.json"
COOLDOWN_SECONDS = 900 # 15 phút

os.makedirs(ARCHIVE_DIR, exist_ok=True)

def get_cooldown_cache():
    try:
        with open(COOLDOWN_CACHE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def update_cooldown_cache(cache):
    with open(COOLDOWN_CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def connect_to_es():
    if not ELK_URL:
        logger.error("Biến môi trường ELK_URL chưa được thiết lập.")
        return None
    try:
        client = Elasticsearch(ELK_URL, request_timeout=10, retry_on_timeout=True, max_retries=3)
        if not client.ping():
            raise ConnectionError("Ping to Elasticsearch failed.")
        return client
    except Exception as e:
        logger.error(f"Lỗi khi kết nối tới Elasticsearch: {e}")
        return None

def _archive_found_log(incident_id: str, content: str):
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        day_dir = os.path.join(ARCHIVE_DIR, today)
        os.makedirs(day_dir, exist_ok=True)
        filename = f"{day_dir}/{incident_id}.log"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        logger.error(f"Lỗi khi lưu trữ log tìm thấy (ID: {incident_id}): {e}")

def process_logs(es_client, processed_log_ids):
    start_time = datetime.now(timezone.utc) - timedelta(seconds=CHECK_INTERVAL_SECONDS * 2)
    keyword_query_string = " OR ".join(f'"{k}"' for k in KEYWORDS)
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start_time.isoformat()}}},
                {"query_string": {"query": keyword_query_string, "default_field": "message", "analyze_wildcard": True}}
            ]
        }
    }
    res = es_client.search(index="filebeat-*", query=query, sort=[{"@timestamp": "desc"}], size=50)

    if not res['hits']['hits']:
        return

    last_alert_time = get_cooldown_cache()
    now_ts = int(time.time())
    
    for hit in reversed(res['hits']['hits']):
        log_id = hit['_id']
        if log_id in processed_log_ids:
            continue

        processed_log_ids.append(log_id)
        source = hit['_source']
        log_message = source.get('message', 'N/A').strip()
        hostname = source.get('host', {}).get('name', 'unknown_host')
        timestamp_str = source.get('@timestamp', 'N/A')

        # --- LOGIC COOLDOWN ---
        # Tạo "dấu vân tay" cho lỗi để cooldown
        error_signature = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[*\d#]+', '', log_message) # Xóa IP, số, ký tự đặc biệt
        error_signature = ' '.join(error_signature.split()[:5]) # Lấy 5 từ đầu
        cache_key = f"{hostname}:{error_signature}"
        
        if (now_ts - last_alert_time.get(cache_key, 0)) < COOLDOWN_SECONDS:
            logger.info(f"Bỏ qua cảnh báo (cooldown) cho: {cache_key}")
            continue
        
        last_alert_time[cache_key] = now_ts
        update_cooldown_cache(last_alert_time)
        
        incident_id = f"{datetime.now().strftime('%H%M%S')}_{hostname}_{log_id[:8]}"
        logger.warning(f"Phát hiện log lỗi (ID: {incident_id}) từ host '{hostname}': {log_message[:300]}")
        _archive_found_log(incident_id, json.dumps(source, indent=2))

        payload = {
            "source": "LogWatcher", "metric": "log_error_detected",
            "instance": hostname, "severity": "warning",
            "trigger_log": log_message, "timestamp": timestamp_str
        }

        try:
            requests.post(ALERT_ENDPOINT, json=payload, timeout=1)
        except requests.exceptions.RequestException:
            pass

        time.sleep(0.5)

if __name__ == "__main__":
    es_client = None
    processed_log_ids = deque(maxlen=MAX_PROCESSED_LOG_IDS)
    while True:
        try:
            if es_client is None:
                es_client = connect_to_es()
            if es_client:
                process_logs(es_client, processed_log_ids)
            else:
                time.sleep(30)
                continue
        except (ConnectionError, TransportError) as e:
            logger.error(f"Mất kết nối tới Elasticsearch: {e}. Sẽ thử kết nối lại.")
            es_client = None
        except Exception as e:
            logger.critical(f"Lỗi nghiêm trọng trong vòng lặp chính: {e}", exc_info=True)
        time.sleep(CHECK_INTERVAL_SECONDS)
