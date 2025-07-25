FROM python:3.10-slim

ENV TZ=Asia/Ho_Chi_Minh
RUN apt-get update && apt-get install -y tzdata && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Đảm bảo thư mục archived_logs tồn tại
RUN mkdir -p /app/archived_logs

CMD ["python", "log_watcher.py"]
