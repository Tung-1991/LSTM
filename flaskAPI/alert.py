import os
import json
import logging
import re
import requests
import yaml # Thêm thư viện yaml
import sys # Thêm sys cho logging ra stdout
from flask import Flask, request, jsonify
from datetime import datetime
# Giả định module elk tồn tại và có hàm get_logs_for_instance
# Nếu elk.py không nằm cùng cấp hoặc cần thay đổi, hãy điều chỉnh import này
from elk import get_logs_for_instance

# --- Cấu hình ứng dụng Flask ---
app = Flask(__name__)

# --- Cấu hình logging ---
# Lấy log level từ biến môi trường, mặc định là INFO
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()

# Cấu hình logger để ghi ra console (stdout), Docker sẽ bắt được log này
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout  # Đảm bảo log được đẩy ra standard output
)

# Đặt tên cho logger theo tên file để dễ phân biệt
logger = logging.getLogger(__name__)

# --- Cấu hình kết nối và thư mục ---
RAG_ENGINE_URL = os.getenv("RAG_ENGINE_URL")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL")

# Đường dẫn thư mục lưu trữ gợi ý AI
ARCHIVE_DIR = "/app/ai_suggestions"
os.makedirs(ARCHIVE_DIR, exist_ok=True)
logger.info(f"Thư mục lưu trữ gợi ý AI: {ARCHIVE_DIR}")

# --- Các hàm xử lý logic ---
def _build_prompt(data: dict) -> str:
    """
    Xây dựng prompt cho RAG Engine dựa trên dữ liệu cảnh báo.
    """
    source = data.get("source", "LSTMDetector")
    instance_ip = data.get("instance", "unknown").split(":")[0]
    
    # Lấy log liên quan từ ELK. Đảm bảo hàm get_logs_for_instance được định nghĩa và hoạt động.
    try:
        elk_logs = get_logs_for_instance(instance_ip, datetime.utcnow())
        log_section = f"**Log hệ thống liên quan (từ ELK):**\n```log\n{elk_logs or 'Không tìm thấy log liên quan.'}\n```"
    except Exception as e:
        logger.error(f"Lỗi khi lấy log từ ELK cho instance {instance_ip}: {e}")
        log_section = "**Log hệ thống liên quan (từ ELK):**\n```log\nKhông thể truy xuất log liên quan do lỗi.\n```"

    json_structure = """```json
{
  "source_document_title": "(Lấy từ metadata.title trong tài liệu RAG. Nếu không có tài liệu, ghi 'Không tìm thấy tài liệu tham khảo')",
  "system_code": "(Lấy từ metadata.system_code)",
  "affected_hosts": "(Lấy từ metadata.hosts, là một danh sách các đối tượng hostname/ip)",
  "diagnosis_summary": "(Tự suy luận một câu chẩn đoán ngắn gọn dựa trên sự cố và tài liệu)",
  "investigation_steps": "(Lấy từ actionable_plan.investigation_steps, là danh sách các bước điều tra)",
  "remediation_playbooks": "(Lấy từ actionable_plan.remediation_playbooks, là danh sách các bước khắc phục)"
}
```"""
    prompt_header = ""
    incident_info = ""

    if source == "LogWatcher":
        prompt_header = "**Sự cố được phát hiện từ Log**"
        incident_info = f"**Log gây ra cảnh báo:**\n`{data.get('trigger_log', 'N/A')}`"
    else: # Mặc định là LSTMDetector hoặc nguồn khác
        prompt_header = "**Sự cố được phát hiện từ Metric (LSTM)**"
        # Bỏ qua các key không cần thiết trong prompt nếu không có giá trị
        metric_details_items = []
        for key, value in data.items():
            if key not in ["source", "severity", "timestamp"] and value is not None:
                metric_details_items.append(f"- {key}: {value}")
        
        if metric_details_items:
            incident_info = f"**Thông tin Metric:**\n" + "\n".join(metric_details_items)
        else:
            incident_info = "**Thông tin Metric:**\nKhông có chi tiết metric cụ thể."
            
    final_prompt = (
        f"{prompt_header}\n\n"
        f"{incident_info}\n\n"
        f"{log_section}\n\n"
        f"**YÊU CẦU:** Dựa vào thông tin sự cố và tài liệu RAG được cung cấp (nếu có), "
        f"hãy điền đầy đủ vào cấu trúc JSON dưới đây. TRẢ VỀ CHỈ MỘT KHỐI JSON. KHÔNG GIẢI THÍCH.\n"
        f"{json_structure}"
    )
    logger.debug(f"Prompt đã tạo cho RAG Engine:\n{final_prompt}")
    return final_prompt

def _parse_rag_response(rag_raw_text: str) -> dict:
    """
    Phân tích phản hồi thô từ RAG Engine để trích xuất JSON.
    """
    try:
        json_match = re.search(r'\{.*\}', rag_raw_text, re.DOTALL)
        if json_match:
            parsed_json = json.loads(json_match.group(0))
            logger.debug(f"Đã parse JSON từ phản hồi RAG: {parsed_json}")
            return parsed_json
        else:
            logger.warning(f"Không tìm thấy khối JSON trong phản hồi từ AI: {rag_raw_text[:500]}...")
            return {"diagnosis_summary": "Phản hồi từ AI không chứa JSON hợp lệ."}
    except json.JSONDecodeError as e:
        logger.error(f"Lỗi khi parse JSON từ AI: {e}. Raw text: {rag_raw_text[:500]}...")
        return {"diagnosis_summary": f"Lỗi phân tích phản hồi từ AI: {e}"}
    except Exception as e:
        logger.error(f"Lỗi không xác định khi parse phản hồi RAG: {e}. Raw text: {rag_raw_text[:500]}...")
        return {"diagnosis_summary": f"Lỗi không xác định khi phân tích phản hồi từ AI: {e}"}

def _format_alert_for_gapo(data: dict, rag_result: dict) -> dict:
    """
    Format cảnh báo thành cấu trúc phù hợp để gửi đến Alertmanager (hoặc Gapo).
    """
    instance = data.get("instance", "unknown")
    metric = data.get("metric", "log_error")
    severity = data.get("severity", "warning").upper()
    
    summary = f"[{severity}] `{rag_result.get('system_code', 'SYSTEM')}` - Phát hiện sự cố trên `{instance}`"
    
    diag = f"**📝 Chẩn đoán:** > {rag_result.get('diagnosis_summary', 'N/A')}"
    sys_code = f"**🖥️ Hệ thống:** `{rag_result.get('system_code', 'N/A')}`"
    doc = f"**📚 Nguồn tri thức:** `{rag_result.get('source_document_title', 'N/A')}`"
    
    hosts_str = "**📍 Máy chủ ảnh hưởng:**\n"
    affected_hosts = rag_result.get('affected_hosts', [])
    if affected_hosts and isinstance(affected_hosts, list):
        hosts_str += "\n".join([f"• {h.get('hostname', 'N/A')} (`{h.get('ip', 'N/A')}`)" for h in affected_hosts])
    else:
        hosts_str += "• Không xác định"
    
    invest_str = "**🔍 Gợi ý điều tra (Investigation):**\n```\n"
    invest_steps = rag_result.get('investigation_steps', [])
    if invest_steps and isinstance(invest_steps, list):
        # Đảm bảo các bước có 'name' và 'command'
        formatted_steps = []
        for i, s in enumerate(invest_steps):
            name = s.get('name', '')
            command = s.get('command', '')
            if name or command: # Chỉ thêm nếu có nội dung
                formatted_steps.append(f"{i+1}. {name}:\n   {command}")
        invest_str += "\n".join(formatted_steps) if formatted_steps else "Không có gợi ý."
    else:
        invest_str += "Không có gợi ý."
    invest_str += "\n```"
    
    remed_str = "**🛠️ Gợi ý xử lý (Remediation):**\n```\n"
    remed_steps = rag_result.get('remediation_playbooks', [])
    if remed_steps and isinstance(remed_steps, list):
        # Đảm bảo các bước có 'name' và 'target'
        formatted_steps = []
        for i, s in enumerate(remed_steps):
            name = s.get('name', '')
            target = s.get('target', '')
            if name or target: # Chỉ thêm nếu có nội dung
                formatted_steps.append(f"{i+1}. {name}:\n   {target}")
        remed_str += "\n".join(formatted_steps) if formatted_steps else "Không có gợi ý."
    else:
        remed_str += "Không có gợi ý."
    remed_str += "\n```"
    
    description = f"{diag}\n\n{sys_code}\n{hosts_str}\n{doc}\n\n---\n\n{invest_str}\n\n{remed_str}"
    
    formatted_alert = {
        "labels": {
            "alertname": f"AI_SRE_{metric}",
            "instance": instance,
            "severity": data.get("severity", "warning")
        },
        "annotations": {
            "summary": summary,
            "description": description.strip()
        }
    }
    logger.debug(f"Cảnh báo đã format: {json.dumps(formatted_alert, indent=2)}")
    return formatted_alert

def _archive_suggestion(data: dict, rag_result: dict):
    """
    Lưu trữ toàn bộ thông tin cảnh báo và gợi ý AI vào file YAML.
    """
    try:
        instance = data.get("instance", "unknown").replace(":", "_").replace("/", "_") # Xử lý các ký tự không hợp lệ trong tên file
        metric = data.get("metric", "log_error")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{ARCHIVE_DIR}/{metric}_{instance}_{timestamp}.yml"

        archive_data = {
            "incident_details": data,
            "ai_suggestion": rag_result,
            "archive_timestamp": datetime.now().isoformat()
        }

        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(archive_data, f, allow_unicode=True, indent=2, sort_keys=False)
        logger.info(f"Đã lưu trữ gợi ý vào file: {filename}")
    except Exception as e:
        logger.error(f"Lỗi khi lưu trữ file gợi ý: {e}", exc_info=True)


@app.route("/alert", methods=["POST"])
def alert_endpoint():
    """
    Endpoint nhận cảnh báo từ các nguồn (LSTM, LogWatcher), gọi RAG Engine
    và chuyển tiếp cảnh báo đã được làm giàu thông tin đến Alertmanager.
    """
    if not RAG_ENGINE_URL:
        logger.error("Biến môi trường RAG_ENGINE_URL chưa được cấu hình. Không thể gọi RAG Engine.")
        return jsonify({"error": "RAG Engine URL not configured"}), 500
    if not ALERTMANAGER_URL:
        logger.error("Biến môi trường ALERTMANAGER_URL chưa được cấu hình. Không thể gửi cảnh báo.")
        return jsonify({"error": "Alertmanager URL not configured"}), 500

    data = request.get_json()
    if not data:
        logger.warning("Request nhận được không có dữ liệu JSON hợp lệ.")
        return jsonify({"error": "Invalid JSON"}), 400

    logger.info(f"Nhận được cảnh báo từ {data.get('source', 'unknown')}: {json.dumps(data)}")

    # Bước 1: Xây dựng prompt cho RAG Engine
    prompt = _build_prompt(data)

    # Bước 2: Gọi RAG Engine
    rag_raw_response = ""
    try:
        logger.debug(f"Đang gọi RAG Engine tại {RAG_ENGINE_URL}...")
        response = requests.post(RAG_ENGINE_URL, json={"message": prompt}, timeout=180) # Timeout 3 phút cho RAG
        response.raise_for_status() # Ném exception nếu response status code là lỗi
        rag_raw_response = response.json().get("reply", "")
        logger.info("Đã nhận phản hồi từ RAG Engine.")
    except requests.exceptions.Timeout:
        logger.error(f"Request tới RAG Engine bị timeout sau 180 giây.")
        rag_raw_response = '{"diagnosis_summary": "Lỗi: RAG Engine phản hồi quá thời gian (Timeout)."}'
    except requests.exceptions.ConnectionError as ce:
        logger.error(f"Lỗi kết nối tới RAG Engine tại {RAG_ENGINE_URL}: {ce}")
        rag_raw_response = '{"diagnosis_summary": "Lỗi: Không thể kết nối tới RAG Engine."}'
    except requests.exceptions.RequestException as re:
        logger.error(f"Lỗi HTTP khi gọi RAG Engine ({re.response.status_code}): {re.response.text}")
        rag_raw_response = f'{{"diagnosis_summary": "Lỗi HTTP từ RAG Engine ({re.response.status_code})."}}'
    except Exception as e:
        logger.error(f"Lỗi không xác định khi gọi RAG Engine: {e}", exc_info=True)
        rag_raw_response = f'{{"diagnosis_summary": "Lỗi không xác định khi gọi RAG Engine: {e}"}}'

    # Bước 3: Parse phản hồi từ RAG Engine
    rag_result = _parse_rag_response(rag_raw_response)

    # Bước 4: Format cảnh báo cho Alertmanager (hoặc Gapo)
    final_alert = _format_alert_for_gapo(data, rag_result)

    # Bước 5: Lưu trữ gợi ý AI (archive)
    _archive_suggestion(data, rag_result)

    # Bước 6: Gửi cảnh báo đã làm giàu thông tin tới Alertmanager
    try:
        logger.info(f"Đang gửi cảnh báo tới Alertmanager tại {ALERTMANAGER_URL}...")
        post_response = requests.post(ALERTMANAGER_URL, json=[final_alert], timeout=15)
        post_response.raise_for_status()
        logger.info("Cảnh báo đã được gửi thành công tới Alertmanager.")
        return jsonify({"status": "processed", "alert_sent": True, "alert_manager_response": post_response.text})
    except requests.exceptions.Timeout:
        logger.error(f"Gửi cảnh báo tới Alertmanager bị timeout sau 15 giây.")
        return jsonify({"status": "error", "alert_sent": False, "message": "Gửi tới Alertmanager bị timeout"}), 500
    except requests.exceptions.ConnectionError as ce:
        logger.error(f"Lỗi kết nối tới Alertmanager tại {ALERTMANAGER_URL}: {ce}")
        return jsonify({"status": "error", "alert_sent": False, "message": "Lỗi kết nối tới Alertmanager"}), 500
    except requests.exceptions.RequestException as re:
        logger.error(f"Lỗi HTTP khi gửi cảnh báo tới Alertmanager ({re.response.status_code}): {re.response.text}")
        return jsonify({"status": "error", "alert_sent": False, "message": f"Lỗi HTTP từ Alertmanager ({re.response.status_code})"}), 500
    except Exception as e:
        logger.error(f"Lỗi không xác định khi gửi cảnh báo tới Alertmanager: {e}", exc_info=True)
        return jsonify({"status": "error", "alert_sent": False, "message": f"Lỗi không xác định: {e}"}), 500

if __name__ == '__main__':
    logger.info("Alert API đã khởi chạy.")
    # Chạy Flask app trên tất cả các interface, cổng 5001.
    # debug=True chỉ nên dùng trong môi trường phát triển, không dùng cho production.
    app.run(host='0.0.0.0', port=5001, debug=False) # Đặt debug=False cho production
