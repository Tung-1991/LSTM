# FILE: flaskAPI/alert.py
# VERSION: 9.4 - FINAL - Sửa lỗi NameError và Logic Thẩm định
# Tác giả: Đối tác lập trình AI (Thi hành theo logic đã thống nhất)

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

# --- Import các module tùy chỉnh ---
import memory

try:
    from elk import get_logs_for_instance
except ImportError:
    # Hàm dự phòng nếu elk.py không tồn tại
    def get_logs_for_instance(*args, **kwargs):
        logging.warning("elk.py not found or failed to import, returning empty log string.")
        return "Could not retrieve logs from ELK."

# --- Cấu hình ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
RAG_API_URL = os.getenv("RAG_API_URL")
SRE_AGENT_URL = os.getenv("SRE_AGENT_URL")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL")
KNOWLEDGE_SOURCE_DIR = os.getenv("KNOWLEDGE_SOURCE_DIR", "/rag_source")
OUTPUT_DIR = "/app/ai_suggestions"
STOP_ON_SUCCESS_KEYWORDS = ['restart', 'reboot', 'fix', 'remedy', 'reload', 'start', 'clear', 'delete']

# --- Logger ---
logger = logging.getLogger('alert-api')
logger.setLevel(LOG_LEVEL)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s - [ALERT-API] - [%(levelname)s] - %(message)s'))
    logger.addHandler(handler)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# --- Khởi tạo ứng dụng Flask ---
app = Flask(__name__)

@lru_cache(maxsize=512)
def load_yaml_from_file(path: str):
    """Đọc và cache nội dung file YAML để tránh đọc lại từ đĩa."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load or parse YAML from {path}: {e}")
        return None

def call_llm(messages: list, incident_id: str) -> str:
    """Hàm gọi LLM chung, có thể dùng cho cả thẩm định và phân tích."""
    if not RAG_API_URL:
        logger.error(f"[{incident_id}] RAG_API_URL is not configured.")
        return "LLM_UNAVAILABLE"
    try:
        payload = {"message": messages[0]['content']}
        timeout = 30 if "Chỉ trả lời 'CÓ' hoặc 'KHÔNG'" in messages[0]['content'] else 120
        response = requests.post(RAG_API_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json().get("reply", "").strip()
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to call LLM API at {RAG_API_URL}: {e}")
        return "LLM_ERROR"

# === [SỬA LỖI NAMEERROR] ĐỊNH NGHĨA ĐẦY ĐỦ CÁC HÀM BỊ THIẾU ===

def dispatch_sre_action(playbook: dict, target_ip: str, target_hostname: str, incident_id: str):
    """Gửi yêu cầu thực thi playbook đến SRE Agent."""
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
        response = requests.post(SRE_AGENT_URL, json=payload, timeout=180)
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

def format_final_alert(incident_id, data, instance, host_alias, analysis, plan, all_exec_results, source, title, system_code, trigger_log):
    """Định dạng cảnh báo cuối cùng để gửi đi."""
    severity_upper = data.get('severity', 'warning').upper()
    safe_title = title.strip()[:200]
    safe_host_alias = host_alias[:120]
    summary = f"[{severity_upper}] {system_code}: {safe_title} on {safe_host_alias}"
    
    description_parts = [f"### 📊 Tóm tắt sự cố", f"> Nguồn tri thức: `{source}`", f"- **Host:** `{instance}` (Alias: `{host_alias}`)"]
    if trigger_log:
        description_parts.append(f"- **Log kích hoạt:** `{trigger_log}`")
    else:
        description_parts.append(f"- **Metric:** `{data.get('metric', 'N/A')}` | **Value:** `{data.get('value', 'N/A')}`")

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

    description_parts.append("\n### 🤖 Chẩn đoán cuối cùng từ AI SRE")
    description_parts.append(f"_{analysis}_")

    manual_steps = (plan.get('investigation_steps', []) or []) + [p for p in (plan.get('remediation_playbooks', []) or []) if not p.get('allow_automation')]
    if manual_steps:
        description_parts.append("\n### 🛠️ Gợi ý các bước xử lý (Thủ công)")
        for s in manual_steps:
            command = s.get('command') or s.get('target', 'N/A').replace('{{TARGET_HOST}}', host_alias)
            description_parts.append(f"- **{s.get('name')}**: `{command}`")

    labels = {"alertname": f"AIOps_{system_code}", "instance": instance, "severity": data.get('severity', 'warning'), "source": "AI_SRE", "host_alias": host_alias}
    if all_exec_results:
        labels["automation_attempted"] = "true"
        labels["automation_status"] = "SUCCESS" if all(res['result'].get('status') == 'SUCCESS' for res in all_exec_results) else "FAILED"
    
    return {"labels": labels, "annotations": {"summary": summary, "description": "\n".join(description_parts)}}

def send_to_alertmanager(payload, incident_id):
    """Gửi cảnh báo đã định dạng đến Alertmanager."""
    if not ALERTMANAGER_URL:
        logger.info(f"[{incident_id}] ALERTMANAGER_URL not set. Skipping send.")
        return
    try:
        res = requests.post(ALERTMANAGER_URL, json=[payload], timeout=15)
        res.raise_for_status()
        logger.info(f"[{incident_id}] Successfully sent alert to Alertmanager.")
    except requests.RequestException as e:
        logger.error(f"[{incident_id}] Failed to send alert to Alertmanager: {e}")

# === KẾT THÚC PHẦN SỬA LỖI NAMEERROR ===

def find_knowledge_candidates(host_identifier: str):
    """Bước 1: Khoanh vùng nhanh các file .yml có hostname liên quan."""
    candidates = []
    if not os.path.exists(KNOWLEDGE_SOURCE_DIR):
        logger.error(f"Knowledge source directory not found: {KNOWLEDGE_SOURCE_DIR}")
        return candidates
    search_keys = {host_identifier}
    if '.' in host_identifier and not re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host_identifier):
         search_keys.add(host_identifier.split('.')[0])
    for root, _, files in os.walk(KNOWLEDGE_SOURCE_DIR):
        for filename in files:
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(root, filename)
                doc = load_yaml_from_file(filepath)
                if not doc: continue
                hosts_in_doc = doc.get('metadata', {}).get('hosts', [])
                if not isinstance(hosts_in_doc, list): continue
                for host_info in hosts_in_doc:
                    if isinstance(host_info, dict) and any(key in {host_info.get('hostname'), host_info.get('ip')} for key in search_keys):
                        candidates.append({'doc': doc, 'host_info': host_info, 'filepath': filepath})
                        break
    return candidates

def get_best_candidate_by_llm_judge(alert_text: str, candidates: list, incident_id: str) -> dict | None:
    """Bước 2: Dùng LLM để thẩm định và tìm ra ứng viên duy nhất."""
    if not candidates:
        return None

    logger.info(f"[{incident_id}] Submitting {len(candidates)} candidates to LLM for judgment...")
    
    relevant_candidates = []
    for candidate in candidates:
        metadata = candidate['doc'].get('metadata', {})
        title = metadata.get('title', 'Không có tiêu đề')
        tags = ", ".join(metadata.get('tags', []))
        
        prompt = (
            f"Bối cảnh: Một log lỗi đã xảy ra. "
            f"Log lỗi: \"{alert_text}\".\n"
            f"Tài liệu hướng dẫn có tiêu đề: \"{title}\" và các tags: \"{tags}\".\n"
            "Câu hỏi: Dựa vào log lỗi, tài liệu hướng dẫn này có liên quan trực tiếp để xử lý không? "
            "Chỉ trả lời 'CÓ' hoặc 'KHÔNG'."
        )
        
        messages = [{"role": "user", "content": prompt}]
        response = call_llm(messages, incident_id)
        
        logger.info(f"[{incident_id}] -> Judgment for '{os.path.basename(candidate['filepath'])}': LLM answered '{response}'")
        
        # === [SỬA LỖI LOGIC] KIỂM TRA CÂU TRẢ LỜI NGHIÊM NGẶT HƠN ===
        # Chỉ chấp nhận nếu câu trả lời bắt đầu bằng "CÓ" (không phân biệt hoa thường)
        first_word = response.split()[0].strip().lower() if response else ""
        if first_word == 'có' or first_word == 'yes':
            relevant_candidates.append(candidate)

    if len(relevant_candidates) == 1:
        logger.warning(f"[{incident_id}] LLM JUDGMENT: Exactly one relevant document found. Proceeding with '{os.path.basename(relevant_candidates[0]['filepath'])}'.")
        return relevant_candidates[0]
    elif len(relevant_candidates) > 1:
        logger.error(f"[{incident_id}] AUTOMATION HALTED: Ambiguous situation. LLM found {len(relevant_candidates)} relevant documents. Escalating to human.")
        return None
    else: # len == 0
        logger.warning(f"[{incident_id}] AUTOMATION SKIPPED: LLM found no relevant documents.")
        return None

def process_incident(data: dict):
    """Hàm xử lý chính cho mỗi sự cố."""
    instance_identifier = data.get("instance", "unknown_instance").split(":")[0]
    incident_id = f"{datetime.now().strftime('%y%m%d_%H%M%S')}_{instance_identifier.replace('.', '_')}"
    logger.info(f"[{incident_id}] === New Incident Received: {data} ===")
    trigger_log = data.get('trigger_log', '')
    alert_content_to_analyze = f"{data.get('metric', '')} {trigger_log}"
    incident_context = f"Sự cố ban đầu: {json.dumps(data)}\n"
    if trigger_log: incident_context += f"Log gây ra sự cố: {trigger_log}\n"
    related_logs = get_logs_for_instance(instance_identifier, around_time=datetime.fromtimestamp(data.get('timestamp', datetime.now().timestamp())), window_minutes=5)
    if related_logs: incident_context += f"Các log liên quan khác:\n{related_logs}"
    
    initial_candidates = find_knowledge_candidates(instance_identifier)
    best_candidate = get_best_candidate_by_llm_judge(alert_content_to_analyze, initial_candidates, incident_id)
    
    all_execution_results, action_plan, knowledge_doc, knowledge_filepath = [], {}, None, None
    host_alias_for_ansible = instance_identifier
    analysis_summary = ""
    
    if best_candidate:
        knowledge_doc, matched_host_info, knowledge_filepath = best_candidate['doc'], best_candidate['host_info'], best_candidate['filepath']
        host_alias_for_ansible = matched_host_info.get('hostname', instance_identifier)
        action_plan = knowledge_doc.get('actionable_plan', {})
        remediation_playbooks = action_plan.get('remediation_playbooks', [])
        if isinstance(remediation_playbooks, list):
            for playbook in remediation_playbooks:
                is_allowed = playbook.get("allow_automation", False)
                has_auto_tag = "[AUTO]" in playbook.get("name", "")
                if is_allowed and has_auto_tag:
                    execution_result = dispatch_sre_action(playbook, matched_host_info.get('ip', instance_identifier), host_alias_for_ansible, incident_id)
                    all_execution_results.append({"name": playbook.get('name'), "result": execution_result})
                    if execution_result.get("status") == "SUCCESS" and any(k in playbook.get('name', '').lower() for k in STOP_ON_SUCCESS_KEYWORDS):
                        logger.warning(f"[{incident_id}] Remediation succeeded. Halting automation.")
                        break
                elif is_allowed and not has_auto_tag:
                    logger.warning(f"[{incident_id}] SKIPPING playbook '{playbook.get('name')}' because it is missing the '[AUTO]' tag.")
    
    automation_summary = "Không có hành động tự động nào được thực hiện."
    if all_execution_results:
        automation_summary = "Kết quả các hành động tự động đã thực thi:\n"
        for res in all_execution_results:
            status = res['result'].get('status', 'N/A')
            output_line = res['result'].get('output', '').strip().splitlines()[-1] if res['result'].get('output') else "N/A"
            automation_summary += f"- Playbook '{res['name']}' có trạng thái = {status}. Kết quả: {output_line[:150]}\n"
    
    historical_context = memory.get_recent_history(instance_identifier)
    
    final_prompt = ""
    if best_candidate:
        final_prompt = (f"Mày là một chuyên gia SRE 20 năm kinh nghiệm. Một kỹ sư mới vào nghề đang gặp log lỗi này: \"{trigger_log}\".\n"
                      f"Đây là tài liệu hướng dẫn xử lý chuẩn của công ty (file {os.path.basename(knowledge_filepath)}):\n---\n{yaml.dump(knowledge_doc, allow_unicode=True)}\n---\n"
                      f"Kết quả các hành động tự động (nếu có): {automation_summary}\n"
                      f"Lịch sử các sự cố tương tự trên máy này: {historical_context}\n"
                      "Dựa vào tất cả thông tin trên, hãy viết một bản phân tích và hướng dẫn chi tiết, từng bước một, cho kỹ sư đó.")
    else:
        final_prompt = (f"Mày là một chuyên gia SRE. Đây là một lỗi mới chưa có tài liệu: \"{trigger_log}\".\n"
                      f"Lịch sử các sự cố trên máy này: {historical_context}\n"
                      "Dựa vào kinh nghiệm của mày, hãy đưa ra chẩn đoán và các bước kiểm tra ban đầu tốt nhất có thể.")
    
    messages = [{"role": "user", "content": final_prompt}]
    analysis_summary = call_llm(messages, incident_id)
    
    short_summary = analysis_summary.splitlines()[0] if analysis_summary else "No AI analysis available."
    memory.add_event(incident_id=incident_id, entity_name=instance_identifier, summary=f"[{data.get('metric', 'log')}] {short_summary}")
    logger.info(f"[{incident_id}] Incident logged to context memory.")
    
    knowledge_source = os.path.basename(knowledge_filepath) if knowledge_filepath else "LLM General Analysis"
    title = knowledge_doc.get('metadata', {}).get('title', f"AI Analysis for {instance_identifier}") if knowledge_doc else f"AI Analysis for {instance_identifier}"
    system_code = knowledge_doc.get('metadata', {}).get('system_code', 'General') if knowledge_doc else "General"
    
    final_alert = format_final_alert(incident_id, data, instance_identifier, host_alias_for_ansible, analysis_summary, action_plan, all_execution_results, knowledge_source, title, system_code, trigger_log)
    send_to_alertmanager(final_alert, incident_id)
    
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(os.path.join(OUTPUT_DIR, f"{incident_id}.md"), "w", encoding='utf-8') as f:
            f.write(f"# {final_alert['annotations']['summary']}\n\n{final_alert['annotations']['description']}")
    except Exception as e:
        logger.error(f"[{incident_id}] Could not write debug markdown file: {e}")
    
    return {"status": "processed", "incident_id": incident_id, "knowledge_source": knowledge_source}

@app.route("/alert", methods=["POST"])
def alert_endpoint():
    data = request.get_json()
    if not data or "instance" not in data:
        return jsonify({"status": "error", "message": "Invalid JSON or missing 'instance'"}), 400
    result = process_incident(data)
    return jsonify(result)

@app.route("/reload", methods=["POST"])
def reload_cache():
    try:
        cleared_items = load_yaml_from_file.cache_info().currsize
        load_yaml_from_file.cache_clear()
        logger.warning(f"YAML cache cleared successfully ({cleared_items} items).")
        return jsonify({"status": "success", "message": f"Cache cleared. {cleared_items} items removed."})
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Đã xác nhận với file memory.py của bạn, không cần gọi init_db()
    logger.info(f"🚀 AI SRE Alerting Service (v9.4 - FINAL) is ready.")
    serve(app, host='0.0.0.0', port=5001, threads=10)
