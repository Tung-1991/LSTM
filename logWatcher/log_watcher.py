import os
import time
import logging
import requests
import sys
from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
from elasticsearch import Elasticsearch, ConnectionError, TransportError
from collections import deque

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
log_file_path = '/app/log_watcher.log'

file_handler = TimedRotatingFileHandler(log_file_path, when="midnight", interval=1, backupCount=7)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [LogWatcher] %(message)s'))

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [LogWatcher] %(message)s'))

logging.basicConfig(
    level=log_level,
    handlers=[file_handler, stream_handler]
)
logger = logging.getLogger(__name__)

ELK_URL = os.getenv("ELK_URL")
ALERT_ENDPOINT = os.getenv("ALERT_ENDPOINT", "http://alert-api:5001/alert")
CHECK_INTERVAL_SECONDS = 60
KEYWORDS = ["error", "failed", "exception", "denied", "timeout", "refused", "critical"]
MAX_PROCESSED_LOG_IDS = 5000

def connect_to_es():
    if not ELK_URL:
        logger.error("Biến môi trường ELK_URL chưa được thiết lập.")
        return None
    try:
        client = Elasticsearch(
            ELK_URL,
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
            request_timeout=10,
            retry_on_timeout=True,
            max_retries=3
        )
        if not client.ping():
            raise ConnectionError("Ping to Elasticsearch failed.")
        logger.info(f"Kết nối thành công tới Elasticsearch tại: {ELK_URL}")
        return client
    except Exception as e:
        logger.error(f"Lỗi khi kết nối tới Elasticsearch: {e}")
        return None

def process_logs(es_client, processed_log_ids):
    start_time = datetime.now(timezone.utc) - timedelta(seconds=CHECK_INTERVAL_SECONDS * 2)
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat()}}},
                    {"query_string": {"query": " OR ".join(KEYWORDS), "fields": ["message"]}}
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "size": 50
    }

    logger.debug(f"Đang truy vấn Elasticsearch với query: {query}")
    res = es_client.search(index="filebeat-*", body=query)
    logger.debug(f"Tìm thấy {res['hits']['total']['value']} log phù hợp.")

    for hit in reversed(res['hits']['hits']):
        log_id = hit['_id']
        if log_id in processed_log_ids:
            continue

        processed_log_ids.append(log_id)
        source = hit['_source']
        log_message = source.get('message', 'N/A').strip()
        hostname = source.get('host', {}).get('name', 'unknown_host')
        timestamp = source.get('@timestamp', 'N/A')

        logger.info(f"Phát hiện log lỗi từ host '{hostname}': {log_message[:200]}")

        payload = {
            "source": "LogWatcher", "metric": "log_error_detected",
            "instance": hostname, "severity": "warning",
            "trigger_log": log_message, "timestamp": timestamp
        }

        try:
            requests.post(ALERT_ENDPOINT, json=payload, timeout=10)
            logger.info(f"Đã gửi cảnh báo thành công cho log từ host: {hostname}")
        except Exception as e:
            logger.error(f"Lỗi khi gửi cảnh báo: {e}")
        
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
                logger.warning(f"Chưa kết nối được Elasticsearch, sẽ thử lại sau 30 giây.")
                time.sleep(30)
                continue

        except (ConnectionError, TransportError) as e:
            logger.error(f"Mất kết nối tới Elasticsearch: {e}. Sẽ thử kết nối lại.")
            es_client = None
        except Exception as e:
            logger.critical(f"Lỗi nghiêm trọng trong vòng lặp chính: {e}", exc_info=True)
        
        logger.info(f"Hoàn tất chu trình. Tạm nghỉ {CHECK_INTERVAL_SECONDS} giây.")
        time.sleep(CHECK_INTERVAL_SECONDS)
