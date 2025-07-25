# FILE: flaskAPI/alert.py
# VERSION: 2.4 - YAML-Immutable & Intelligent Execution
import os
import json
import logging
import re
import requests
import yaml
import sys
from flask import Flask, request, jsonify
from datetime import datetime
from functools import lru_cache
from waitress import serve

# Giả lập hàm elk nếu không tồn tại để tránh lỗi
try:
    from elk import get_logs_for_instance
except ImportError:
    def get_logs_for_instance(*args, **kwargs):
        logging.warning("elk.py not found or failed to import, returning empty log string.")
        return "Could not retrieve logs from ELK."

# --- Cấu hình ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
RAG_API_URL = os.getenv("RAG_API_URL", "http://172.27.119.158:5005/ask")
SRE_AGENT_URL = os.getenv("SRE_AGENT_URL", "http://sre-agent:5002/execute")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://192.168.111.111:9093/api/v1/alerts")
KNOWLEDGE_SOURCE_DIR = os.getenv("KNOWLEDGE_SOURCE_DIR", "/rag_source")
OUTPUT_DIR = "/app/ai_suggestions"
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() in ('true', '1', 't')
# [MỚI v2.4] Các từ khóa trong tên playbook để "dừng thông minh"
STOP_ON_SUCCESS_KEYWORDS = ['restart', 'fix', 'reboot', 'start', 'enable', 'remedy']

# --- Logger ---
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
os.makedirs(OUTPUT_DIR, exist_ok=True)

@lru_cache(maxsize=128)
def find_knowledge_by_host(host_identifier: str):
    logger.info(f"[KNOWLEDGE_SEARCH] Searching for knowledge related to '{host_identifier}' in '{KNOWLEDGE_SOURCE_DIR}'")
    if not os.path.exists(KNOWLEDGE_SOURCE_DIR):
        logger.warning(f"[KNOWLEDGE_SEARCH] Directory '{KNOWLEDGE_SOURCE_DIR}' does not exist.")
        return None, None, None

    search_keys = [host_identifier]
    is_ip = re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host_identifier) is not None
    if not is_ip:
        hostname_part = host_identifier.split('.')[0]
        if hostname_part != host_identifier:
            search_keys.append(hostname_part)
    
    for key in search_keys:
        for root, _, files in os.walk(KNOWLEDGE_SOURCE_DIR):
            for filename in files:
                if filename.endswith((".yml", ".yaml")):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            doc = yaml.safe_load(f)
                        hosts_in_doc = doc.get('metadata', {}).get('hosts', [])
                        if not isinstance(hosts_in_doc, list): continue

                        for host_info in hosts_in_doc:
                            if isinstance(host_info, dict) and key in (host_info.get('hostname'), host_info.get('ip')):
                                logger.info(f"[KNOWLEDGE_SEARCH] >> MATCH FOUND << File: '{filepath}', Host: {host_info}")
                                return doc, host_info, filepath
                    except yaml.YAMLError as ye:
                        logger.error(f"YAML syntax error in {filepath}: {ye}")
                    except Exception as e:
                        logger.error(f"Error processing knowledge file {filepath}: {e}", exc_info=True)

    logger.warning(f"[KNOWLEDGE_SEARCH] >> NO MATCH << for '{host_identifier}'. Proceeding with AI Fallback.")
    return None, None, None

def call_llm_for_analysis(prompt: str, incident_id: str) -> str:
    if not RAG_API_URL:
        logger.error(f"[{incident_id}] RAG_API_URL is not configured. AI analysis is disabled.")
        return "AI analysis is unavailable due to configuration error."
    try:
        response = requests.post(RAG_API_URL, json={"message": prompt}, timeout=120, verify=VERIFY_SSL)
        response.raise_for_status()
        reply = response.json().get("reply", "No reply content from AI.")
        logger.info(f"[{incident_id}] Received AI analysis successfully.")
        return reply.strip()
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to call RAG API at {RAG_API_URL}: {e}")
        return f"AI analysis failed due to connection error: {e}"

def dispatch_sre_action(playbook: dict, target_ip: str, target_hostname: str, incident_id: str):
    if not SRE_AGENT_URL:
        logger.warning(f"[{incident_id}] SRE_AGENT_URL is not configured. Skipping automation.")
        return {"status": "SKIPPED", "output": "SRE_AGENT_URL not configured."}

    command_template = playbook.get("target")
    if not command_template or not isinstance(command_template, str):
        logger.error(f"[{incident_id}] Invalid or missing 'target' in playbook: {playbook.get('name')}")
        return {"status": "ERROR", "output": "Invalid playbook target."}
    
    final_command = command_template.replace("{{TARGET_HOST}}", str(target_hostname)).replace("{{TARGET_IP}}", str(target_ip))

    logger.warning(f"[{incident_id}] DISPATCHING AUTOMATION: '{playbook.get('name')}' on host '{target_hostname}'")
    logger.info(f"[{incident_id}] Final command: '{final_command}'")

    payload = {"command": final_command, "target_host": target_hostname}
    try:
        response = requests.post(SRE_AGENT_URL, json=payload, timeout=180, verify=VERIFY_SSL)
        response.raise_for_status()
        logger.info(f"[{incident_id}] SRE Agent responded for action '{playbook.get('name')}'")
        return response.json()
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to dispatch command to SRE Agent: {e}")
        error_output = str(e)
        if getattr(e, 'response', None) is not None:
            try:
                error_output = e.response.json().get('output', e.response.text)
            except json.JSONDecodeError:
                error_output = e.response.text
        else: 
            error_output = f"Agent unreachable or request timed out: {str(e)}"
        
        return {"status": "ERROR", "output": f"Failed to contact SRE Agent: {error_output}"}

# ========================================================================
# [NÂNG CẤP v2.4] Hàm process_incident
# ========================================================================
def process_incident(data: dict):
    raw_instance = data.get("instance", "unknown_instance")
    instance_identifier = raw_instance.split(":")[0]
    incident_id = f"{datetime.now().strftime('%y%m%d_%H%M%S')}_{instance_identifier.replace('.', '_')}"
    logger.info(f"[{incident_id}] === New Incident Received for '{instance_identifier}' ===")

    # --- Bước 1: Lấy ngữ cảnh ban đầu (sự cố & tri thức) ---
    incident_context = f"Sự cố ban đầu: {json.dumps(data)}\n"
    if data.get("source") == "LogWatcher":
        incident_context += f"Log gây ra sự cố: {data.get('trigger_log', 'N/A')}\n"
    
    related_logs = get_logs_for_instance(instance_identifier, around_time=datetime.fromtimestamp(data.get('timestamp', datetime.now().timestamp())), window_minutes=5)
    if related_logs:
        log_limit = 8000
        if len(related_logs) > log_limit: 
            related_logs = related_logs[:log_limit] + "\n... (logs truncated)"
            logger.warning(f"[{incident_id}] Related logs were truncated to {log_limit} characters.")
        incident_context += f"Các log liên quan khác:\n{related_logs}"

    knowledge_doc, matched_host_info, knowledge_filepath = find_knowledge_by_host(instance_identifier)

    # --- Bước 2: Thực thi chuỗi playbook tự động (TRƯỚC KHI GỌI AI) ---
    all_execution_results = []
    action_plan = {}
    host_alias_for_ansible = instance_identifier
    
    if knowledge_doc and matched_host_info:
        host_alias_for_ansible = matched_host_info.get('hostname', instance_identifier)
        action_plan = knowledge_doc.get('actionable_plan', {})
        remediation_playbooks = action_plan.get('remediation_playbooks', [])
        
        if isinstance(remediation_playbooks, list):
            for playbook in remediation_playbooks:
                if playbook.get("allow_automation") is True:
                    playbook_name = playbook.get('name', '').lower()
                    logger.info(f"[{incident_id}] Found automation-allowed playbook: '{playbook_name}'")
                    
                    execution_result = dispatch_sre_action(
                        playbook,
                        target_ip=matched_host_info.get('ip', instance_identifier),
                        target_hostname=host_alias_for_ansible,
                        incident_id=incident_id
                    )
                    
                    all_execution_results.append({ "name": playbook.get('name'), "result": execution_result })

                    # [LOGIC DỪNG THÔNG MINH v2.4]
                    if execution_result.get("status") == "SUCCESS" and any(keyword in playbook_name for keyword in STOP_ON_SUCCESS_KEYWORDS):
                        logger.warning(f"[{incident_id}] Remediation playbook '{playbook_name}' succeeded. Halting automation sequence as a precaution.")
                        break
    
    # --- Bước 3: Tổng hợp ngữ cảnh cho AI ---
    automation_context = "Không có hành động tự động nào được thực hiện."
    if all_execution_results:
        automation_context = "Các hành động tự động sau đã được thực thi:\n"
        for res in all_execution_results:
            status = res['result'].get('status', 'N/A')
            output_line = res['result'].get('output', '').strip().splitlines()[-1] if res['result'].get('output') else "N/A"
            automation_context += f"- Playbook '{res['name']}': Trạng thái = {status}. Kết quả tóm tắt: {output_line[:150]}\n"

    # --- Bước 4: Gọi AI để có Phân tích Cuối cùng ---
    knowledge_content = "Không có tri thức cụ thể."
    knowledge_source = "AI Fallback"
    if knowledge_doc:
        knowledge_content = knowledge_doc.get('content', 'Không có nội dung mô tả.')
        if knowledge_filepath:
            knowledge_source = os.path.basename(knowledge_filepath)

    prompt = f"""Bạn là một kỹ sư SRE chuyên gia. Một sự cố đã xảy ra. Hệ thống đã tự động thực hiện một số hành động.
Hãy phân tích tất cả thông tin dưới đây và đưa ra một bản chẩn đoán cuối cùng súc tích, chuyên nghiệp.

**1. DỮ LIỆU SỰ CỐ BAN ĐẦU (Host: {instance_identifier}):**
---
{incident_context}
---
**2. TRI THỨC HỆ THỐNG (Từ file {knowledge_source}):**
---
{knowledge_content}
---
**3. KẾT QUẢ TỰ ĐỘNG HÓA ĐÃ THỰC THI:**
---
{automation_context}
---
**YÊU CẦU:** Dựa vào cả 3 nguồn thông tin trên, hãy trả lời:
- **Chẩn đoán:** (1-2 câu) Nguyên nhân gốc rễ có thể là gì? Sự cố đã được khắc phục chưa?
- **Hành động tiếp theo:** (Nếu cần) Đề xuất các bước kiểm tra hoặc xử lý thủ công tiếp theo.
"""
    analysis_summary = call_llm_for_analysis(prompt, incident_id)

    # --- Bước 5: Tạo và Gửi Alert ---
    system_code = knowledge_doc.get('metadata', {}).get('system_code', 'General') if knowledge_doc else "General"
    title = knowledge_doc.get('metadata', {}).get('title', f"AI Analysis for {instance_identifier}") if knowledge_doc else f"AI Analysis for {instance_identifier}"

    final_alert = format_final_alert(
        incident_id, data, instance_identifier, host_alias_for_ansible, analysis_summary,
        action_plan, all_execution_results, knowledge_source, 
        title, system_code, data.get('trigger_log')
    )
    
    send_to_alertmanager(final_alert, incident_id)
    try:
        with open(os.path.join(OUTPUT_DIR, f"{incident_id}.md"), "w", encoding='utf-8') as f:
            f.write(f"# {final_alert['annotations']['summary']}\n\n{final_alert['annotations']['description']}")
    except Exception as e:
        logger.error(f"[{incident_id}] Could not write debug markdown file: {e}")

    return {"status": "processed", "incident_id": incident_id, "knowledge_source": knowledge_source}

# ========================================================================
# [NÂNG CẤP v2.4] Hàm format_final_alert
# ========================================================================
def format_final_alert(incident_id, data, instance, host_alias, analysis, plan, all_exec_results, source, title, system_code, trigger_log):
    severity_upper = data.get('severity', 'warning').upper()
    safe_title = title.strip()[:200]
    safe_host_alias = host_alias[:120]
    summary = f"[{severity_upper}] {system_code}: {safe_title} on {safe_host_alias}"

    description_parts = ["### 📊 Tóm tắt sự cố"]
    description_parts.append(f"- **Host:** `{instance}` (Alias: `{host_alias}`)")
    if trigger_log: 
        description_parts.append(f"- **Log kích hoạt:** `{trigger_log}`")
    else: 
        description_parts.append(f"- **Metric:** `{data.get('metric', 'N/A')}` | **Value:** `{data.get('value', 'N/A')}`")

    # [MỚI v2.4] Phần 2: Hành động tự động (Hiển thị trước để người vận hành thấy ngay)
    if all_exec_results:
        description_parts.append("\n### ⚡ Hành động Tự động đã thực thi")
        for res_item in all_exec_results:
            name = res_item.get("name")
            result = res_item.get("result", {})
            status = result.get("status", "UNKNOWN")
            output = result.get("output", "No output from agent.")

            description_parts.append(f"\n- **Playbook:** `{name}`")
            if status == "SUCCESS":
                recap_line = re.search(r"PLAY RECAP.*?\n(.*?)\n", output, re.DOTALL)
                summary_output = recap_line.group(1).strip() if recap_line else "Completed successfully."
                description_parts.append(f"  - **Trạng thái:** ✅ **THÀNH CÔNG**")
                description_parts.append(f"  - **Kết quả:** `{summary_output}`")
            else:
                error_summary = output.splitlines()[-1] if output else "Agent returned an error."
                description_parts.append(f"  - **Trạng thái:** ❌ **THẤT BẠI / LỖI** (`{status}`)")
                description_parts.append(f"  - **Chi tiết lỗi:** `{error_summary}`")
    
    # Phần 3: Chẩn đoán của AI (Sau khi đã có mọi thông tin)
    description_parts.append("\n### 🤖 Chẩn đoán cuối cùng từ AI SRE")
    description_parts.append(f"_{analysis}_")
    description_parts.append(f"> Nguồn tri thức: `{source}`")

    # Phần 4: Gợi ý các bước thủ công
    manual_steps = (plan.get('investigation_steps', []) or []) + [p for p in (plan.get('remediation_playbooks', []) or []) if p.get('allow_automation') is not True]
    if manual_steps:
        description_parts.append("\n### 🛠️ Gợi ý các bước xử lý (Thủ công)")
        for s in manual_steps:
            command = s.get('command') or s.get('target', 'N/A').replace('{{TARGET_HOST}}', host_alias)
            description_parts.append(f"- **{s.get('name')}**: `{command}`")

    # Tạo labels cuối cùng
    labels = { "alertname": f"AIOps_{system_code}", "instance": instance, "severity": data.get('severity', 'warning'), "source": "AI_SRE", "host_alias": host_alias }
    if all_exec_results:
        labels["automation_attempted"] = "true"
        # Trạng thái tổng hợp: nếu dù chỉ 1 playbook thất bại thì coi là failed.
        final_status = "SUCCESS" if all(res['result'].get('status') == 'SUCCESS' for res in all_exec_results) else "FAILED"
        labels["automation_status"] = final_status.lower()

    return {
        "labels": labels,
        "annotations": { "summary": summary, "description": "\n".join(description_parts) }
    }

def send_to_alertmanager(payload, incident_id):
    if not ALERTMANAGER_URL:
        logger.info(f"[{incident_id}] ALERTMANAGER_URL not set. Skipping send.")
        return
    try:
        res = requests.post(ALERTMANAGER_URL, json=[payload], timeout=15, verify=VERIFY_SSL)
        res.raise_for_status()
        logger.info(f"[{incident_id}] Successfully sent alert to Alertmanager.")
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to send alert to Alertmanager: {e}")

@app.route("/alert", methods=["POST"])
def alert_endpoint():
    data = request.get_json()
    if not data or "instance" not in data:
        return jsonify({"status": "error", "message": "Invalid JSON or missing 'instance'"}), 400
    
    result = process_incident(data)
    return jsonify(result)

@app.route("/reload", methods=["POST"])
def reload_cache():
    """Endpoint to clear the LRU cache for knowledge files."""
    try:
        cleared_count = find_knowledge_by_host.cache_info().currsize
        find_knowledge_by_host.cache_clear()
        logger.warning(f"Knowledge cache cleared successfully. ({cleared_count} items removed)")
        return jsonify({"status": "success", "message": "Cache cleared."}), 200
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Sử dụng Waitress thay vì Gunicorn với nhiều worker để đảm bảo lru_cache
    # hoạt động nhất quán. Endpoint /reload sẽ xóa cache trên tiến trình duy nhất này.
    logger.info("🚀 AI SRE Alerting Service (v2.4 - YAML-Immutable & Intelligent Execution) is ready.")
    logger.info(f"Knowledge Source Directory: {KNOWLEDGE_SOURCE_DIR}")
    logger.info(f"SSL Verification for outgoing requests: {VERIFY_SSL}")
    if not RAG_API_URL:
        logger.error("FATAL: RAG_API_URL environment variable is not set!")
    serve(app, host='0.0.0.0', port=5001, threads=10)
