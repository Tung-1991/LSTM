import os
import logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Tắt log thừa của thư viện
logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

# Lấy cấu hình từ biến môi trường
ELK_URL = os.getenv("ELK_URL")
es_client = None

# Kết nối tới Elasticsearch khi module được import
if ELK_URL:
    try:
        es_client = Elasticsearch(
            ELK_URL,
            request_timeout=10,
            max_retries=1
        )
        if not es_client.ping():
            logging.error("[ELK] Không thể ping tới Elasticsearch.")
            es_client = None
    except Exception as e:
        es_client = None
        logging.error(f"[ELK] Lỗi kết nối Elasticsearch: {e}")

def get_logs_for_instance(instance_ip: str, around_time: datetime, window_minutes: int = 5, keywords: list = None) -> str:
    """
    Truy vấn log từ ELK.
    - Nếu 'keywords' được cung cấp, chỉ tìm log chứa các từ khóa đó.
    - Nếu không, lấy 30 log gần nhất.
    """
    if not es_client:
        return "" # Im lặng nếu không kết nối được

    start_time_utc = (around_time - timedelta(minutes=window_minutes)).isoformat() + "Z"
    end_time_utc = (around_time + timedelta(minutes=window_minutes)).isoformat() + "Z"

    # Xây dựng câu query cơ bản
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start_time_utc, "lte": end_time_utc}}}
            ],
            "filter": [
                # Giả định instance_ip có thể là hostname hoặc IP
                {"query_string": {"query": f"host.name: \"{instance_ip}\" OR host.ip: \"{instance_ip}\""}}
            ]
        }
    }

    # Nếu có keywords, thêm điều kiện lọc vào query
    if keywords and isinstance(keywords, list):
        keyword_query = " OR ".join(keywords)
        query["bool"]["must"].append({
            "query_string": {
                "query": keyword_query,
                "fields": ["message"]
            }
        })

    try:
        response = es_client.search(index="filebeat-*", query=query, size=30, sort=[{"@timestamp": "desc"}])
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return ""

        # Sắp xếp lại theo thứ tự thời gian tăng dần để dễ đọc
        clean_logs = [hit['_source'].get('message', '').strip() for hit in reversed(hits)]
        return "\n".join(clean_logs)
    except Exception as e:
        logging.error(f"[ELK] Lỗi khi truy vấn Elasticsearch: {e}")
        return ""
