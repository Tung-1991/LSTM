import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import requests
import pandas as pd
import numpy as np
import time
import logging
import re
import json
import glob
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense

log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger('lstm-detector')
logger.setLevel(log_level)

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.propagate = False

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('matplotlib').setLevel(logging.WARNING)
logging.getLogger('tensorflow').setLevel(logging.ERROR)

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.111.111:9090")
ALERT_ENDPOINT = os.environ.get("ALERT_ENDPOINT", "http://alert-api:5001/alert")
MODELS_DIR = "/app/models"
OUTPUTS_DIR = "/app/outputs"
COOLDOWN_CACHE_FILE = "/app/cooldown_cache.json"

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(OUTPUTS_DIR, exist_ok=True)

METRICS = {
    "cpu": '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
    "memory": '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100',
    "disk": '(node_filesystem_size_bytes{mountpoint="/"} - node_filesystem_avail_bytes{mountpoint="/"}) / node_filesystem_size_bytes{mountpoint="/"} * 100',
}

def query_metric(metric_name, promql, start, end, step="60"):
    url = f"{PROMETHEUS_URL}/api/v1/query_range"
    params = {"query": promql, "start": start, "end": end, "step": step}
    try:
        r = requests.get(url, params=params, timeout=15)
        r.raise_for_status()
        response_json = r.json()
        if 'data' not in response_json or 'result' not in response_json['data']:
            return []
        all_df = []
        for result in response_json['data']['result']:
            df = pd.DataFrame(result['values'], columns=["timestamp", "value"])
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            df['value'] = pd.to_numeric(df['value'], errors='coerce').dropna()
            if df.empty:
                continue
            df['instance'] = result['metric'].get('instance', 'unknown')
            all_df.append(df.set_index("timestamp"))
        return all_df
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"Lỗi HTTP khi truy vấn metric '{metric_name}'. Status: {http_err.response.status_code}, Response: {http_err.response.text}")
        return []
    except Exception as e:
        logger.error(f"Lỗi không xác định khi truy vấn metric '{metric_name}': {e}", exc_info=True)
        return []

def should_alert(current_value, predicted_value, threshold):
    logger.debug(f"Checking alert: current={current_value:.2f}, predicted={predicted_value:.2f}, threshold={threshold:.2f}")
    if current_value > 90:
        logger.warning(f"[ALERT RULE] Triggered by hard threshold (> 90%) for value {current_value:.2f}")
        return True
    is_significant_jump = current_value > (predicted_value + threshold)
    if is_significant_jump and current_value > 25:
        logger.warning(f"[ALERT RULE] Triggered by significant jump ({current_value:.2f} > predicted={predicted_value:.2f} + thresh={threshold:.2f})")
        return True
    return False

def get_cooldown_cache():
    try:
        with open(COOLDOWN_CACHE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def update_cooldown_cache(cache):
    with open(COOLDOWN_CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def detect_anomaly(data, metric_name, model_cache):
    last_alert_time = get_cooldown_cache()
    for df in data:
        if len(df) < 70:
            logger.debug(f"Skipping {metric_name} on {df['instance'].iloc[0]}: insufficient data points ({len(df)} < 70).")
            continue
        scaler = MinMaxScaler()
        scaled_data = scaler.fit_transform(df[['value']].values)
        time_step = 60
        last_sequence = scaled_data[-time_step:]
        if len(last_sequence) < time_step:
            continue
        X_live = np.array([last_sequence])
        instance = df['instance'].iloc[0]
        instance_id = re.sub(r'\W+', '_', instance.lower())
        hour_slot = time.localtime(df.index[-1].timestamp()).tm_hour // 6
        model_path = f"{MODELS_DIR}/model_{metric_name}_{instance_id}_slot{hour_slot}.keras"
        model = model_cache.get(model_path)
        if not model:
            logger.info(f"Model not found in cache. Training new model for {metric_name} on {instance} (slot {hour_slot}).")
            X_train, y_train = [], []
            for i in range(len(scaled_data) - time_step):
                X_train.append(scaled_data[i:i + time_step])
                y_train.append(scaled_data[i + time_step])
            if len(X_train) < 10:
                logger.warning(f"Not enough training data for {metric_name} on {instance}. Skipping model training.")
                continue
            X_train, y_train = np.array(X_train), np.array(y_train)
            model = Sequential([LSTM(50, input_shape=(time_step, 1)), Dense(1)])
            model.compile(optimizer='adam', loss='mse')
            model.fit(X_train, y_train, epochs=10, batch_size=32, verbose=0)
            model.save(model_path)
            model_cache[model_path] = model
            logger.info(f"Model trained, saved and cached: {model_path}")
        pred = model.predict(X_live, verbose=0)
        predicted_value = float(scaler.inverse_transform(pred)[0][0])
        current_value = float(df['value'].iloc[-1])
        threshold = predicted_value * 0.15
        if should_alert(current_value, predicted_value, threshold):
            now_ts = int(time.time())
            cache_key = f"{instance}:{metric_name}"
            if (now_ts - last_alert_time.get(cache_key, 0)) < 600:
                logger.info(f"[COOLDOWN] Skipping alert for {cache_key} as it is in cooldown period.")
                continue
            last_alert_time[cache_key] = now_ts
            update_cooldown_cache(last_alert_time)
            payload = {
                "metric": metric_name, "instance": instance, "value": round(current_value, 2),
                "predicted_value": round(predicted_value, 2), "threshold": round(threshold, 2),
                "timestamp": int(df.index[-1].timestamp()),
                "severity": "critical" if current_value > 90 else "warning"
            }
            logger.warning(f"[ANOMALY DETECTED] {json.dumps(payload)}")
            try:
                requests.post(ALERT_ENDPOINT, json=payload, timeout=5)
                logger.info(f"[ALERT SENT] Successfully sent alert to {ALERT_ENDPOINT}.")
            except Exception as e:
                logger.error(f"[ALERT FAILED] Could not send alert to {ALERT_ENDPOINT}: {e}")
            try:
                plt.figure(figsize=(12, 6))
                plt.plot(df.index, df['value'], label='Actual Value')
                plt.axhline(y=predicted_value, color='orange', linestyle='--', label=f'Predicted Value ({predicted_value:.2f})')
                plt.scatter(df.index[-1], current_value, color='red', s=100, zorder=5, label=f'Anomaly Detected ({current_value:.2f})')
                plt.title(f"Anomaly Detected: {metric_name} on {instance}")
                plt.xlabel("Time")
                plt.ylabel("Value")
                plt.legend()
                plt.grid(True)
                plt.tight_layout()
                filename = f"{OUTPUTS_DIR}/anomaly_{metric_name}_{instance_id}_{now_ts}.png"
                plt.savefig(filename)
                plt.close()
                logger.info(f"Anomaly chart saved to: {filename}")
            except Exception as e:
                logger.error(f"Failed to save anomaly chart: {e}", exc_info=True)

def main():
    logger.info("LSTM Detector service starting...")
    model_cache = {}
    logger.info(f"Scanning for existing models in {MODELS_DIR}...")
    model_files = glob.glob(f"{MODELS_DIR}/*.keras")
    if model_files:
        for f in model_files:
            try:
                model_cache[f] = load_model(f)
                logger.debug(f"Successfully loaded model into cache: {f}")
            except Exception as e:
                logger.error(f"Failed to load model {f}: {e}")
        logger.info(f"Finished loading. {len(model_cache)} models are now in cache.")
    else:
        logger.info("No pre-trained models found. Models will be trained on the fly.")
    while True:
        now = int(time.time())
        start_time = now - 3600 * 6
        logger.info("===== Starting new anomaly detection cycle =====")
        for metric_name, promql in METRICS.items():
            logger.info(f"Querying data for metric: '{metric_name}'")
            dfs = query_metric(metric_name, promql, start_time, now)
            if dfs:
                logger.info(f"Found data for {len(dfs)} instance(s). Detecting anomalies...")
                detect_anomaly(dfs, metric_name, model_cache)
            else:
                logger.info(f"No data returned for metric: '{metric_name}'")
        logger.info("===== Cycle finished. Waiting for 120 seconds... =====")
        time.sleep(120)

if __name__ == "__main__":
    main()
