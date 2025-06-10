from flask import Flask, request, jsonify
import requests
import time
import os
import json
import logging
import subprocess

app = Flask(__name__)

# Thiết lập logging
logging.basicConfig(
    filename='/app/flask_alert.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Biến môi trường cấu hình
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://192.168.111.111:9093/api/v1/alerts")
GENERATOR_URL = os.getenv("GENERATOR_URL", "http://aiagent.local/LSTM")
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT")
logging.info(f"🔍 Sử dụng LLM_ENDPOINT = {LLM_ENDPOINT}")

@app.route("/alert", methods=["POST"])
def receive_alert():
    data = request.get_json()
    ts = int(data.get("timestamp", time.time()))
    instance = data.get("instance", "unknown")
    metric = data.get("metric", "unknown")
    value = float(data.get("value", 0))

    # Cấu trúc alert gửi Alertmanager
    alert = {
        "labels": {
            "alertname": "AI_Anomaly_Detected",
            "severity": data.get("severity", "critical"),
            "instance": instance,
            "metric": metric
        },
        "annotations": {
            "summary": f"Bat thuong: {metric} tai {instance}",
            "description": f"Gia tri: {value} luc {time.ctime(ts)}"
        },
        "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "endsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts + 300)),
        "generatorURL": GENERATOR_URL
    }

    # Gửi tới Alertmanager
    for attempt in range(3):
        try:
            response = requests.post(ALERTMANAGER_URL, json=[alert], timeout=5)
            if response.status_code == 200:
                logging.info(f"[{attempt+1}/3] ALERT SENT:\n{json.dumps(alert, indent=2, ensure_ascii=False)}")
                break
            else:
                logging.warning(f"[{attempt+1}/3] Alertmanager response: {response.status_code}")
        except Exception as e:
            logging.error(f"[{attempt+1}/3] Loi khi gui canh bao: {e}")
            time.sleep(2)

    # Nếu không có LLM thì bỏ qua
    if not LLM_ENDPOINT:
        logging.warning("⚠️ Không có biến môi trường LLM_ENDPOINT, bỏ qua gọi LLM.")
        return jsonify({"status": "success", "note": "LLM skipped"}), 200

    # Prompt cho LLM
    prompt = f"""Phát hiện bất thường hệ thống:
- Máy: {instance}
- Metric: {metric}
- Giá trị: {value}
- Mức độ: {data.get('severity', 'critical')}
Bạn là trợ lý AI có kiến thức về hạ tầng và dịch vụ, hãy đề xuất cách xử lý."""

    llm_payload = {
        "model": "llama-3-13b-instruct.Q4_K_M.gguf",
        "messages": [
            {"role": "system", "content": "Bạn là trợ lý AI giám sát hệ thống."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1024,
        "temperature": 0.4,
        "top_p": 0.9,
        "top_k": 40
    }

    try:
        llm_res = requests.post(LLM_ENDPOINT, json=llm_payload, timeout=10)
        if llm_res.status_code == 200:
            llm_reply = llm_res.json()["choices"][0]["message"]["content"]
            logging.info(f"🧐 LLM đề xuất:\n{llm_reply}")

            # Ghi lại đề xuất ra file JSON
            suggest_dir = "/app/suggestions"
            os.makedirs(suggest_dir, exist_ok=True)
            suggest_path = os.path.join(suggest_dir, f"suggest_{ts}.json")
            with open(suggest_path, "w", encoding="utf-8") as f:
                json.dump({
                    "time": ts,
                    "instance": instance,
                    "metric": metric,
                    "value": value,
                    "suggestion": llm_reply
                }, f, ensure_ascii=False, indent=2)

            # Tự động reset nếu metric là nginx và CPU cao
            if metric == "nginx" and value >= 90:
                ip = instance.split(":")[0]
                try:
                    subprocess.run(["ssh", f"vagrant@{ip}", "sudo systemctl restart nginx"], check=True)
                    logging.info(f"✅ Đã reset nginx trên {ip}")
                except Exception as e:
                    logging.error(f"❌ Lỗi khi reset nginx trên {ip}: {e}")
        else:
            logging.warning(f"❗ LLM HTTP {llm_res.status_code}: {llm_res.text}")
    except Exception as e:
        logging.error(f"❌ Lỗi gọi LLM: {e}")

    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
