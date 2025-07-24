FROM python:3.10-slim

# Cài đặt và cấu hình múi giờ GMT+7
ENV TZ=Asia/Ho_Chi_Minh
RUN apt-get update && apt-get install -y tzdata && rm -rf /var/lib/apt/lists/*

WORKDIR /sre_agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Đảm bảo thư mục logs tồn tại
RUN mkdir -p /app/logs

# Chạy service trên port 5002
CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "1", "agent:app"]
