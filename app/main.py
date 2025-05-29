import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import requests
import pandas as pd
import numpy as np
import time
import logging
import re
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense
import tensorflow as tf

# GHI LOG ra file de tien debug
logging.basicConfig(
    filename='/app/monitoring_log.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# PHAT HIEN GPU hoac chay CPU
try:
    gpus = tf.config.list_physical_devices('GPU')
    if gpus:
        for i, gpu in enumerate(gpus):
            details = tf.config.experimental.get_device_details(gpu)
            compute = details.get('compute_capability', 'N/A')
            logging.info(f"[GPU DETECTED] GPU {i}: {gpu.name} - Compute Capabilities: {compute}")
    else:
        logging.info("[CPU MODE] Khong phat hien GPU, su dung CPU.")
except Exception as e:
    logging.error(f"Loi khi kiem tra GPU: {e}")

# Lay bien moi truong hoac mac dinh
PROMETHEUS = os.getenv("PROMETHEUS_URL", "http://192.168.111.111:9090")
ALERT_ENDPOINT = os.getenv("ALERT_ENDPOINT", "http://alert-api:5000/alert")

# Cac bieu thuc PromQL cho CPU, RAM, Disk da tinh theo %
METRICS = {
    "cpu": '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
    "memory": '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100',
    "disk": '(1 - (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})) * 100',

    # Network usage %
    "net_rx": '(rate(node_network_receive_bytes_total{device="eth0"}[5m]) / 125000000) * 100',
    "net_tx": '(rate(node_network_transmit_bytes_total{device="eth0"}[5m]) / 125000000) * 100',

    # Disk IO usage %
    "disk_read": '(rate(node_disk_read_bytes_total{device="sda"}[5m]) / 500000000) * 100',
    "disk_write": '(rate(node_disk_written_bytes_total{device="sda"}[5m]) / 500000000) * 100'


    # --- Bổ sung có thể dùng sau ---
    #"cpu_load1": 'node_load1',  # Load trung bình 1 phút
    #"inode_usage": '(1 - (node_filesystem_files_free{mountpoint="/"} / node_filesystem_files{mountpoint="/"})) * 100',
    #"swap": '(node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes) / node_memory_SwapTotal_bytes * 100',
    #"context_switch": 'rate(node_context_switches_total[5m])',  # số lượng context switching
    #"interrupts": 'rate(node_intr_total[5m])'  # hardware interrupts
}


# Bo nho alert cu de tranh spam va cache model theo slot
last_alert_time = {}
model_cache = set()

# Truy van du lieu tu Prometheus (6h gan nhat)
def query_metric(metric, start, end, step="60"):
    url = f"{PROMETHEUS}/api/v1/query_range"
    params = {"query": metric, "start": start, "end": end, "step": step}
    r = requests.get(url, params=params).json()
    if 'data' not in r or 'result' not in r['data']:
        logging.warning(f"[PROMETHEUS EMPTY] No data for query: {metric}")
        return []
    results = r['data']['result']
    all_df = []
    for result in results:
        df = pd.DataFrame(result['values'], columns=["timestamp", "value"])
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        df['value'] = df['value'].astype(float)
        df['application'] = result['metric'].get('application', 'unknown')
        df['instance'] = result['metric'].get('instance', 'unknown')
        all_df.append(df.set_index("timestamp"))
    return all_df

# Logic danh gia co nen gui canh bao khong dua vao nguong dong
# Muc do su dung tang manh bat thuong so voi trung binh

def should_alert(metric_name, current_value, mean_value):
    if current_value < 15:
        return False
    if current_value < 25:
        return current_value > mean_value * 3.5
    elif current_value < 35:
        return current_value > mean_value * 2.8
    elif current_value < 50:
        return current_value > mean_value * 1.8
    elif current_value < 65:
        return current_value > mean_value * 1.4
    elif current_value < 75:
        return current_value > mean_value * 1.2
    elif current_value < 85:
        return current_value > mean_value * 1.05
    else:
        return True

# Ham chinh phat hien bat thuong tu chuoi du lieu

def detect_anomaly(data, metric_name):
    global last_alert_time, model_cache
    now_ts = int(time.time())
    for df in data:
        scaler = MinMaxScaler()
        scaled = scaler.fit_transform(df[['value']])

        # Tao tap du lieu theo chuoi thoi gian 60 diem
        time_step = 60
        X, y = [], []
        for i in range(len(scaled) - time_step):
            X.append(scaled[i:i+time_step])
            y.append(scaled[i+time_step])
        X, y = np.array(X), np.array(y)

        # Neu du lieu it hon 10 mau thi bo qua
        if len(X) < 10:
            continue

        instance = df['instance'].iloc[0]
        application = df['application'].iloc[0]
        instance_id = re.sub(r'\W+', '_', instance.lower())
        app_id = re.sub(r'\W+', '_', application.lower()) if application else metric_name

        # Chia slot theo 6h trong ngay (0-6, 6-12, 12-18, 18-24)
        hour_slot = time.localtime().tm_hour // 6
        model_path = f"/tmp/model_{metric_name}_{app_id}_{instance_id}_slot{hour_slot}.keras"

        # Neu model da xu ly trong vong nay thi bo qua
        if model_path in model_cache:
            continue
        model_cache.add(model_path)

        model = None
        if os.path.exists(model_path):
            try:
                file_age_days = (time.time() - os.path.getmtime(model_path)) / 86400
                if file_age_days > 7:
                    logging.info(f"[MODEL EXPIRED] {model_path} > 7 days → retrain")
                    os.remove(model_path)
                else:
                    model = load_model(model_path)
                    logging.info(f"[MODEL LOAD] {model_path}")
            except Exception as e:
                logging.error(f"[MODEL LOAD FAIL] {model_path}: {e}")
                model = None

        # Train model neu chua co hoac bi xoa
        if model is None:
            model = Sequential([
                LSTM(32, input_shape=(time_step, 1)),
                #LSTM(100, return_sequences=True, input_shape=(time_step, 1)),
                #LSTM(50, return_sequences=True),
                #LSTM(25),
                Dense(1)
            ])

            model.build(input_shape=(None, time_step, 1))

            model.compile(optimizer='adam', loss='mse')
            history = model.fit(X, y, epochs=5, batch_size=32, verbose=0)
            model.save(model_path)
            os.utime(model_path, (time.time(), time.time()))
            logging.info(f"[MODEL TRAIN] Saved: {model_path} (loss: {history.history['loss'][-1]:.6f})")

        # Du doan va so sanh voi thuc te
        pred = model.predict(X)
        pred_inv = scaler.inverse_transform(pred)
        y_inv = scaler.inverse_transform(y)

        abs_errors = np.abs(y_inv - pred_inv)
        threshold = np.percentile(abs_errors, 90)  # Ngưỡng bất thường top 10%
        errors = y_inv - pred_inv
        last_errors = [errors[-i][0] for i in range(1, 6)]
        valid_errors = [e for e in last_errors if e > threshold and e > 0]

        current_value = float(df['value'].iloc[-1])
        mean_value = df['value'].mean()
        cache_key = f"{metric_name}_{instance_id}"

        if current_value < mean_value:
           logging.info(f"[SKIP] {metric_name} @ {instance_id} → current={current_value:.2f} < mean={mean_value:.2f} → Không cảnh báo")
           continue


        # Gui canh bao neu co 3/5 loi gan nhat > nguong va gia tri hien tai bat thuong
        if len(valid_errors) >= 3 and should_alert(metric_name, current_value, mean_value):
            if cache_key in last_alert_time and now_ts - last_alert_time[cache_key] < 600:
                logging.info(f"[SKIPPED] Cooldown active for {cache_key}")
                continue

            last_alert_time[cache_key] = now_ts
            payload = {
                "metric": metric_name,
                "instance": instance,
                "application": application,
                "value": round(current_value, 2),
                "timestamp": now_ts,
                "severity": "critical" if current_value > 95 else "warning"
            }

            logging.warning(f"[ANOMALY DETECTED] {payload}, mean={mean_value:.2f}, threshold={threshold:.2f}, errors={last_errors}")
            try:
                response = requests.post(ALERT_ENDPOINT, json=payload)
                if response.status_code == 200:
                    logging.info(f"[ALERT SENT] {metric_name} @ {instance}")
                else:
                    logging.error(f"[ALERT ERROR] {response.status_code}")
            except Exception as e:
                logging.error(f"[EXCEPTION] Alert failed: {e}")

            # Ve bieu do va luu anh
            df_plot = df.iloc[time_step:].copy()
            df_plot['actual'] = y_inv.flatten()
            df_plot['predicted'] = pred_inv.flatten()
            df_plot['anomaly'] = (errors.flatten() > threshold) & (errors.flatten() > 0)

            plt.figure(figsize=(12, 6))
            plt.plot(df_plot.index, df_plot['actual'], label='Actual')
            plt.plot(df_plot.index, df_plot['predicted'], label='Predicted')
            plt.scatter(df_plot.index[df_plot['anomaly']], df_plot['actual'][df_plot['anomaly']], color='red', label='Anomaly')
            plt.title(f"LSTM - {metric_name} - {instance_id}")
            plt.xlabel('Time')
            plt.ylabel('Value')
            plt.legend()
            plt.tight_layout()
            os.makedirs("/app/outputs", exist_ok=True)
            filename = f"/app/outputs/anomaly_{metric_name}_{app_id}_{instance_id}_slot{hour_slot}_{time.strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(filename)
            plt.close()
            logging.info(f"[PLOT SAVED] {filename}")

# Vong lap chinh chay moi 60s

def main():
    while True:
        now = int(time.time())
        start = now - 3600 * 6
        model_cache.clear()  # reset cache moi vong
        logging.info("===== VONG KIEM TRA MOI =====")
        for metric_name, promql in METRICS.items():
            logging.info(f"[CHECKING] {metric_name}")
            dfs = query_metric(promql, start, now)
            detect_anomaly(dfs, metric_name)
        time.sleep(60)

if __name__ == "__main__":
    main()
