# FILE: sre_agent/agent.py
# VERSION: 2.0 - Simplified Executor
import os
import json
import logging
import logging.handlers
import sys
import paramiko
from flask import Flask, request, jsonify
from waitress import serve
from datetime import datetime

app = Flask(__name__)

# --- Cấu hình Logger ---
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
log_dir = "/app/logs"
os.makedirs(log_dir, exist_ok=True)
logger = logging.getLogger('sre-agent')
logger.setLevel(log_level)
if not logger.handlers:
    # Các handler giữ nguyên như bạn đã thiết lập
    file_handler = logging.handlers.TimedRotatingFileHandler(
        os.path.join(log_dir, 'sre_agent.log'), when="midnight", interval=1, backupCount=7, encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter('%(asctime)s - [SRE-AGENT] - %(levelname)s - %(message)s'))
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter('%(asctime)s - [SRE-AGENT] - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
logger.propagate = False
logging.getLogger('paramiko').setLevel(logging.WARNING)

# --- Cấu hình SSH từ biến môi trường ---
SSH_USER = os.getenv("SSH_USER")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "/app/ssh_keys/id_rsa")
# Đổi tên biến này để rõ ràng hơn, nhưng giữ nguyên ANSIBLE_CONTROLLER_IP để tương thích ngược
SSH_HOST_IP = os.getenv("SSH_HOST_IP", os.getenv("ANSIBLE_CONTROLLER_IP"))

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.route("/execute", methods=["POST"])
def execute_command():
    if not all([SSH_USER, SSH_HOST_IP]):
        msg = "SSH_USER hoặc SSH_HOST_IP chưa được cấu hình."
        logger.error(msg)
        return jsonify({"status": "ERROR", "output": msg}), 500

    data = request.get_json()
    # Nhận lệnh cuối cùng để thực thi
    command_to_execute = data.get("command")
    target_host_info = data.get("target_host", "unknown") # Chỉ dùng để logging

    if not command_to_execute:
        msg = "Dữ liệu JSON không hợp lệ, thiếu key 'command'."
        logger.error(f"Invalid request received: {data}")
        return jsonify({"status": "ERROR", "output": msg}), 400

    request_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    logger.info(f"[{request_id}] Received execution request for target '{target_host_info}'. Command: '{command_to_execute}'")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        logger.info(f"[{request_id}] Reading private key from: {SSH_KEY_PATH}")
        private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)

        logger.info(f"[{request_id}] Connecting to Ansible controller ({SSH_HOST_IP}) as user '{SSH_USER}'...")
        ssh.connect(SSH_HOST_IP, username=SSH_USER, pkey=private_key, timeout=20)
        
        logger.info(f"[{request_id}] Connection successful. Executing command...")
        stdin, stdout, stderr = ssh.exec_command(command_to_execute, timeout=300) # Timeout 5 phút

        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8', errors='ignore').strip()
        error = stderr.read().decode('utf-8', errors='ignore').strip()
        ssh.close()
        logger.info(f"[{request_id}] SSH connection closed.")

        if exit_code == 0:
            logger.info(f"[{request_id}] Command executed SUCCESSFULLY. Exit code: {exit_code}.")
            # Log output để debug nhưng không trả về quá nhiều
            if output:
                logger.debug(f"[{request_id}] STDOUT:\n{output}")
            return jsonify({"status": "SUCCESS", "exit_code": exit_code, "output": output or "Command ran successfully with no output."})
        else:
            full_output = f"STDERR:\n{error}\n\nSTDOUT:\n{output}".strip()
            logger.error(f"[{request_id}] Command FAILED. Exit code: {exit_code}. Details:\n{full_output}")
            # Trả về status FAILED nhưng HTTP 200 OK để alert-api xử lý
            return jsonify({"status": "FAILED", "exit_code": exit_code, "output": full_output})

    except FileNotFoundError:
        msg = f"SSH key file not found at: {SSH_KEY_PATH}"
        logger.critical(f"[{request_id}] {msg}")
        return jsonify({"status": "ERROR", "output": msg}), 500
    except paramiko.AuthenticationException:
        msg = f"SSH authentication failed. Check user '{SSH_USER}' and the SSH key."
        logger.critical(f"[{request_id}] {msg}")
        return jsonify({"status": "ERROR", "output": msg}), 500
    except Exception as e:
        msg = f"An unexpected error occurred in SRE Agent: {str(e)}"
        logger.critical(f"[{request_id}] {msg}", exc_info=True)
        return jsonify({"status": "ERROR", "output": msg}), 500


if __name__ == "__main__":
    print("🚀 SRE Agent (Simplified Executor) - Ready for Commands...")
    print(f"   - SSH Host IP (Ansible Controller): {SSH_HOST_IP}")
    print(f"   - SSH User:                         {SSH_USER}")
    print(f"   - SSH Key Path:                     {SSH_KEY_PATH}")
    serve(app, host='0.0.0.0', port=5002, threads=4)
