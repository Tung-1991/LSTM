# FILE: flaskAPI/elk.py
# VERSION: 3.0 - Refactored for Accuracy
import os
import logging
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch

# --- Logger (không đổi) ---
logger = logging.getLogger('elk-module')
logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - [ELK-MODULE] - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

# --- Elasticsearch Client (không đổi) ---
ELK_URL = os.getenv("ELK_URL")
es_client = None
if ELK_URL:
    try:
        es_client = Elasticsearch(ELK_URL, request_timeout=10, max_retries=1)
        if not es_client.ping():
            logger.error("Ping to Elasticsearch failed.")
            es_client = None
    except Exception as e:
        logger.error(f"Elasticsearch connection error: {e}")
        es_client = None

# --- [SỬA] Hàm tìm Index dựa trên thời gian sự cố, không phải thời gian hiện tại ---
def _get_index_pattern_for_time(target_time: datetime) -> str:
    """Tạo ra chuỗi index pattern cho ngày của target_time và ngày trước đó."""
    target_date = target_time.astimezone(timezone.utc).date()
    previous_date = target_date - timedelta(days=1)
    
    # Tạo pattern cho cả hai ngày để phòng trường hợp log kéo dài qua nửa đêm (giờ UTC)
    target_pattern = f"*-{target_date.strftime('%Y.%m.%d')}"
    previous_pattern = f"*-{previous_date.strftime('%Y.%m.%d')}"
    
    return f"{target_pattern},{previous_pattern}"


def get_logs_for_instance(instance_ip: str, around_time: datetime, window_minutes: int = 5, keywords: list = None) -> str:
    if not es_client:
        return "Could not get logs: Elasticsearch client not available."

    if around_time.tzinfo is None:
        around_time = around_time.astimezone()

    start_time_utc = (around_time - timedelta(minutes=window_minutes)).isoformat()
    end_time_utc = (around_time + timedelta(minutes=window_minutes)).isoformat()

    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start_time_utc, "lte": end_time_utc}}}
            ],
            "filter": [
                {"query_string": {"query": f"host.name: \"{instance_ip}\" OR agent.hostname: \"{instance_ip}\""}}
            ]
        }
    }

    if keywords and isinstance(keywords, list):
        keyword_query = " OR ".join(keywords)
        # --- [SỬA] Dùng lại query đáng tin cậy hơn ---
        query["bool"]["must"].append({
            "query_string": {
                "query": keyword_query,
                "default_field": "message",
                "analyze_wildcard": True
            }
        })

    try:
        # --- [SỬA] Dùng hàm tìm index mới, chính xác hơn ---
        index_pattern = _get_index_pattern_for_time(around_time)
        
        response = es_client.search(
            index=index_pattern, 
            query=query, 
            size=30, 
            sort=[{"@timestamp": "desc"}], 
            ignore_unavailable=True
        )

        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return ""

        clean_logs = [hit['_source'].get('message', '').strip() for hit in reversed(hits)]
        return "\n".join(clean_logs)
    except Exception as e:
        logger.error(f"Error querying Elasticsearch for instance logs: {e}")
        return f"Error retrieving logs: {e}"

