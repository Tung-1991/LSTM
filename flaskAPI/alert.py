from flask import Flask, request, jsonify
import requests
import time
import os
import json
import logging

app = Flask(__name__)

# Ghi log ra file de tien debug neu container bi restart
logging.basicConfig(
    filename='/app/flask_alert.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Dia chi Alertmanager va URL sinh ra alert
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://192.168.111.111:9093/api/v1/alerts")
GENERATOR_URL = os.getenv("GENERATOR_URL", "http://aiagent.local/LSTM")

@app.route("/alert", methods=["POST"])
def receive_alert():
    # Nhan du lieu JSON tu LSTM gui sang
    data = request.get_json()
    ts = int(data.get("timestamp", time.time()))

    # Cau truc canh bao theo chuan Alertmanager
    alert = {
        "labels": {
            "alertname": "AI_Anomaly_Detected",
            "severity": data.get("severity", "critical"),
            "instance": data.get("instance", "unknown"),
            "metric": data.get("metric", "unknown")
        },
        "annotations": {
            "summary": f"Bat thuong: {data.get('metric')} tai {data.get('instance')}",
            "description": f"Gia tri: {data.get('value')} luc {time.ctime(ts)}"
        },
        "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "endsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts + 300)),  # Alert tu ket thuc sau 5 phut
        "generatorURL": GENERATOR_URL
    }

    success = False  # Bien co de kiem tra da gui thanh cong chua

    # Gui canh bao toi da 3 lan neu loi, moi lan cach nhau 2s
    for attempt in range(3):
        try:
            response = requests.post(ALERTMANAGER_URL, json=[alert], timeout=5)
            if response.status_code == 200:
                logging.info(f"[{attempt+1}/3] ALERT SENT:\n{json.dumps(alert, indent=2, ensure_ascii=False)}")
                logging.info(f"Alertmanager response: {response.status_code}")
                success = True
                break
            else:
                logging.warning(f"[{attempt+1}/3] Alertmanager response: {response.status_code}")
        except Exception as e:
            logging.error(f"[{attempt+1}/3] Loi khi gui canh bao: {e}")
            time.sleep(2)

    if not success:
        return jsonify({"status": "error", "message": "Failed after 3 retries"}), 500

    return jsonify({"status": "success"}), 200

# Chay Flask app tren tat ca dia chi IP, cong 5000
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
