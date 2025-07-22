FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY log_watcher.py .

# Chạy script khi container khởi động
CMD ["python", "log_watcher.py"]
