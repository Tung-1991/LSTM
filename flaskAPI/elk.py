import os
import logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Lấy cấu hình từ biến môi trường
ELK_URL = os.getenv("ELK_URL")
es_client = None

# Kết nối tới Elasticsearch khi module được import
if ELK_URL:
    try:
        # [SỬA LỖI] Thêm headers tùy chỉnh vào đây
        custom_headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        es_client = Elasticsearch(
            ELK_URL,
            headers=custom_headers,  # Thêm custom_headers vào đây
            request_timeout=10,
            max_retries=1
        )
        if not es_client.ping():
            logging.error("Không thể ping tới Elasticsearch.")
            es_client = None
    except Exception as e:
        es_client = None
        logging.error(f"Lỗi kết nối Elasticsearch: {e}")

def get_logs_for_instance(instance_ip: str, around_time: datetime, window_minutes: int = 5) -> str:
    """
    Truy vấn log từ ELK.
    Trả về một chuỗi log đã được làm sạch, hoặc chuỗi rỗng nếu có lỗi/không tìm thấy.
    """
    if not es_client:
        logging.warning("Bỏ qua truy vấn ELK vì chưa kết nối được.")
        return "" # [SỬA] Trả về chuỗi rỗng thay vì câu báo lỗi

    start_time_utc = (around_time - timedelta(minutes=window_minutes)).isoformat() + "Z"
    end_time_utc = (around_time + timedelta(minutes=window_minutes)).isoformat() + "Z"

    query = {
        "size": 30, # Lấy 20 dòng log gần nhất
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": start_time_utc, "lte": end_time_utc}}}],
                "filter": [
                    {"term": {"host.ip": instance_ip}}
                ]
            }
        }
    }

    try:
        response = es_client.search(index="filebeat-*", body=query)
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return "" # Không tìm thấy log, trả về chuỗi rỗng

        # Chỉ lấy trường message cho gọn
        clean_logs = [hit['_source'].get('message', '').strip() for hit in hits]
        return "\n".join(clean_logs)
    except Exception as e:
        logging.error(f"Lỗi khi truy vấn Elasticsearch: {e}")
        return "" # [SỬA] Có lỗi cũng trả về chuỗi rỗng
