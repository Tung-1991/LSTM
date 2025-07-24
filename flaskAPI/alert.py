# FILE: flaskAPI/alert.py
# VERSION: 2.1 - Patched Knowledge-First Dispatcher
import os
import json
import logging
import re
import requests
import yaml
import sys
from flask import Flask, request, jsonify
from datetime import datetime
from waitress import serve
from functools import lru_cache

# Import các hàm từ các file khác
try:
    from elk import get_logs_for_instance
except ImportError:
    def get_logs_for_instance(*args, **kwargs):
        logging.warning("elk.py not found, returning empty log string.")
        return "Could not retrieve logs from ELK."

# --- CẤU HÌNH TỪ BIẾN MÔI TRƯỜỜNG ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
# FIX 3: Chấp nhận cả biến cũ và biến mới để tăng tính tương thích
RAG_API_URL = os.getenv("RAG_API_URL", os.getenv("RAG_ENGINE_URL")) 
SRE_AGENT_URL = os.getenv("SRE_AGENT_URL", "http://sre-agent:5002")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://192.168.111.111:9093/api/v1/alerts")
KNOWLEDGE_SOURCE_DIR = os.getenv("KNOWLEDGE_SOURCE_DIR", "/rag_source")

# --- THIẾT LẬP LOGGING ---
logger = logging.getLogger('alert-api')
logger.setLevel(LOG_LEVEL)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - [ALERT-API] - [%(levelname)s] - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.propagate = False
logging.getLogger('urllib3').setLevel(logging.WARNING)

app = Flask(__name__)

# --- CÁC HÀM HELPER & LOGIC CỐT LÕI ---

@lru_cache(maxsize=128)
def find_knowledge_yaml_by_host(host_key: str):
    """
    Tìm kiếm file YML dựa trên host_key (có thể là hostname hoặc IP).
    FIX 1: Đã thêm logic so khớp cả IP và hostname.
    Trả về (filepath, yaml_doc, matched_host_dict)
    """
    if not os.path.exists(KNOWLEDGE_SOURCE_DIR):
        logger.error(f"Thư mục tri thức '{KNOWLEDGE_SOURCE_DIR}' không tồn tại.")
        return None, None, None
    try:
        for filename in os.listdir(KNOWLEDGE_SOURCE_DIR):
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(KNOWLEDGE_SOURCE_DIR, filename)
                with open(filepath, 'r', encoding='utf-8') as f:
                    doc = yaml.safe_load(f)
                    hosts = doc.get('metadata', {}).get('hosts', [])
                    if isinstance(hosts, list):
                        for host in hosts:
                            # So khớp cả hostname và ip
                            if isinstance(host, dict) and host_key in (host.get('hostname'), host.get('ip')):
                                logger.info(f"Tìm thấy file tri thức '{filename}' cho host '{host_key}'.")
                                return filepath, doc, host
    except Exception as e:
        logger.error(f"Lỗi khi quét kho tri thức: {e}")
    return None, None, None

def get_current_metrics_summary(instance_ip: str, initial_data: dict) -> str:
    """Tạo một bản tóm tắt metric từ dữ liệu ban đầu."""
    metric = initial_data.get('metric')
    if metric:
        return f"- Metric Trigger: {metric}\n- Current Value: {initial_data.get('value')}\n- Predicted Value: {initial_data.get('predicted_value')}"
    return "N/A (Cảnh báo được kích hoạt bởi log)"

def call_llm_for_analysis(prompt: str, incident_id: str) -> str:
    """Hàm chuyên dụng để gọi LLM và chỉ lấy về câu trả lời."""
    if not RAG_API_URL:
        logger.warning(f"[{incident_id}] RAG_API_URL/RAG_ENGINE_URL is not set. Cannot get AI analysis.")
        return "AI analysis is unavailable due to configuration error."
    try:
        logger.info(f"[{incident_id}] Sending analysis prompt to RAG API.")
        response = requests.post(RAG_API_URL, json={"message": prompt}, timeout=120)
        response.raise_for_status()
        reply = response.json().get("reply", "No reply content from AI.")
        logger.info(f"[{incident_id}] Received analysis from AI.")
        return reply
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to call RAG API: {e}")
        return f"AI analysis failed due to connection error: {e}"

def dispatch_automated_action(playbook: dict, target_host_ip: str, host_alias: str, incident_id: str):
    """
    Gửi một hành động tự động cụ thể đến SRE Agent.
    FIX 2: Đã sử dụng host_alias cho playbook và thêm placeholder {{TARGET_IP}}.
    """
    if not SRE_AGENT_URL:
        logger.warning(f"[{incident_id}] SRE_AGENT_URL is not set. Skipping automation.")
        return None

    command_template = playbook.get("target")
    if not command_template:
        logger.error(f"[{incident_id}] Playbook '{playbook.get('name')}' is missing 'target' command.")
        return None

    # Thay thế cả 2 placeholder để YAML linh hoạt hơn
    final_command = (command_template
                     .replace("{{TARGET_HOST}}", host_alias)
                     .replace("{{TARGET_IP}}", target_host_ip))

    logger.warning(f"[{incident_id}] DISPATCHING AUTOMATION: '{playbook.get('name')}' on host '{target_host_ip}'. Command: '{final_command}'")
    payload = {"command": final_command, "target_host": host_alias} # Gửi host_alias để logging trong SRE Agent

    try:
        response = requests.post(f"{SRE_AGENT_URL}/execute", json=payload, timeout=180)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to dispatch command to SRE Agent: {e}")
        return {"status": "ERROR", "output": f"Failed to contact SRE Agent: {e}"}

def format_final_alert(incident: dict):
    # (Hàm này không thay đổi)
    instance = incident['instance']
    severity = incident['severity']
    analysis = incident['analysis']
    action_plan = incident['action_plan']
    execution_result = incident['execution_result']
    knowledge_source = incident['knowledge_source']

    summary = f"[{severity.upper()}] {analysis.get('title', 'AI-Driven Alert')} on {instance} (Source: {os.path.basename(knowledge_source) if knowledge_source != 'AI Fallback' else knowledge_source})"
    
    description_parts = [
        f"🔎 **Chẩn đoán từ AI:** {analysis.get('summary', 'N/A')}",
        f"🖥 **Host:** {instance}",
        f"📝 **Nguồn tri thức:** {os.path.basename(knowledge_source) if knowledge_source != 'AI Fallback' else knowledge_source}",
    ]
    if execution_result:
        description_parts.append("\n--- **Hành động tự động** ---")
        status = execution_result.get("status", "UNKNOWN")
        output = execution_result.get('output', 'No output.')
        description_parts.append(f"✅ **Trạng thái:** {status}")
        description_parts.append(f"📋 **Kết quả:**\n```\n{output[:500]}\n```")

    manual_steps = action_plan.get('investigation_steps', []) + [p for p in action_plan.get('remediation_playbooks', []) if not p.get('allow_automation')]
    if manual_steps:
        description_parts.append("\n--- **Gợi ý các bước thủ công** ---")
        for step in manual_steps:
            description_parts.append(f"- **{step.get('name')}**: `{step.get('command') or step.get('target')}`")

    return {
        "labels": { "alertname": f"AIOps_{analysis.get('system_code', 'General')}", "instance": instance, "severity": severity.lower(), "source": "AI_SRE_Platform" },
        "annotations": { "summary": summary, "description": "\n".join(description_parts) }
    }


def process_incident(initial_data: dict, incident_id: str):
    instance_ip = initial_data.get("instance", "unknown").split(":")[0]
    event_time = datetime.fromtimestamp(initial_data.get('timestamp', int(datetime.now().timestamp())))
    
    logger.info(f"[{incident_id}] Enriching data for instance '{instance_ip}'.")
    metrics_summary = get_current_metrics_summary(instance_ip, initial_data)
    logs_summary = get_logs_for_instance(instance_ip, around_time=event_time, window_minutes=5)
    
    incident = { "id": incident_id, "instance": instance_ip, "severity": initial_data.get("severity", "warning"), "initial_alert": initial_data, "metrics": metrics_summary, "logs": logs_summary, "knowledge_source": "AI Fallback", "action_plan": {}, "analysis": {}, "execution_result": None }

    # FIX 1 (Sử dụng): Tìm kiếm và nhận về 3 giá trị
    filepath, doc, matched_host = find_knowledge_yaml_by_host(instance_ip)

    if doc and matched_host:
        logger.info(f"[{incident_id}] Found knowledge YAML. Processing with 'YAML-First' strategy.")
        incident['knowledge_source'] = filepath
        incident['action_plan'] = doc.get('actionable_plan', {})
        metadata = doc.get('metadata', {})
        
        prompt = f"""Bạn là một kỹ sư SRE. Một sự cố đã xảy ra trên host {instance_ip}. 
Dưới đây là tri thức đã được kiểm duyệt và dữ liệu sự cố thực tế. Hãy đọc và đưa ra một bản tóm tắt chẩn đoán ngắn gọn.

**TRI THỨC CÓ SẴN (Từ file {os.path.basename(filepath)}):**
---
{doc.get('content', 'Không có nội dung mô tả.')}
---
**DỮ LIỆU SỰ CỐ THỰC TẾ:**
---
- **Metrics:** {metrics_summary}
- **Logs:** {logs_summary or 'Không có log bất thường nào được tìm thấy.'}
---
**YÊU CẦU:** Đưa ra một câu chẩn đoán ngắn gọn (1-2 câu).
"""
        incident['analysis']['summary'] = call_llm_for_analysis(prompt, incident_id)
        incident['analysis']['title'] = metadata.get('title', 'Incident Analysis')
        incident['analysis']['system_code'] = metadata.get('system_code', 'UNKNOWN')

        # FIX 2 (Sử dụng): Thực thi hành động với alias chính xác
        host_alias_for_ansible = matched_host.get('hostname', instance_ip)
        for playbook in incident['action_plan'].get('remediation_playbooks', []):
            if playbook.get("allow_automation") is True:
                incident['execution_result'] = dispatch_automated_action(playbook, instance_ip, host_alias_for_ansible, incident_id)
                break
    else:
        logger.info(f"[{incident_id}] No specific YAML found. Using RAG fallback strategy.")
        prompt = f"Phân tích sự cố sau trên host {instance_ip} và đề xuất giải pháp...\n**Dữ liệu sự cố:**\n- Initial Alert: {json.dumps(incident['initial_alert'])}\n- Relevant Metrics: {incident['metrics']}\n- Relevant Logs: {incident['logs'] or 'Không có log bất thường.'}\nHãy trả lời với một chẩn đoán ngắn gọn."
        ai_response = call_llm_for_analysis(prompt, incident_id)
        incident['analysis']['summary'] = ai_response
        incident['analysis']['title'] = f"AI Analysis for {instance_ip}"
        incident['analysis']['system_code'] = "General"
        incident['action_plan'] = {"remediation_playbooks": []}

    final_alert_payload = format_final_alert(incident)
    logger.info(f"[{incident_id}] Final alert created. Summary: {final_alert_payload['annotations']['summary']}")
    try:
        with open(os.path.join("ai_suggestions", f"{incident_id}.md"), "w", encoding='utf-8') as f:
            f.write(f"# {final_alert_payload['annotations']['summary']}\n\n{final_alert_payload['annotations']['description']}")
    except Exception as e:
        logger.error(f"[{incident_id}] Could not write debug markdown file: {e}")

    if ALERTMANAGER_URL:
        try:
            res = requests.post(ALERTMANAGER_URL, json=[final_alert_payload], timeout=15)
            res.raise_for_status()
            logger.info(f"[{incident_id}] Successfully sent alert to Alertmanager.")
        except requests.RequestException as e:
            logger.error(f"[{incident_id}] Failed to send alert to Alertmanager: {e}")
            
    return incident


@app.route("/alert", methods=["POST"])
def alert_endpoint():
    data = request.get_json()
    if not data or "instance" not in data:
        return jsonify({"status": "error", "message": "Invalid JSON or missing 'instance'"}), 400

    instance_ip = data.get("instance", "unknown").split(":")[0]
    incident_id = f"{datetime.now().strftime('%y%m%d_%H%M%S')}_{instance_ip.replace('.', '_')}"
    
    logger.info(f"[{incident_id}] === New Incident Received for instance '{instance_ip}' ===")
    
    result = process_incident(data, incident_id)
    
    return jsonify({"status": "processed", "incident_id": incident_id, "knowledge_source": result['knowledge_source']})

if __name__ == '__main__':
    logger.info("🚀 AI SRE Alerting Service (v2.1 - Patched) is ready.")
    logger.info(f"Knowledge Source Directory: {KNOWLEDGE_SOURCE_DIR}")
    if not RAG_API_URL:
        logger.error("FATAL: RAG_API_URL or RAG_ENGINE_URL environment variable is not set!")
    else:
        logger.info(f"RAG API URL: {RAG_API_URL}")

    serve(app, host='0.0.0.0', port=5001, threads=10)
