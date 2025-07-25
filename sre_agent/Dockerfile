FROM python:3.10-slim

ENV TZ=Asia/Ho_Chi_Minh
RUN apt-get update && apt-get install -y tzdata && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Thêm --timeout 180 để Gunicorn chờ 3 phút
CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "1", "--timeout", "180", "agent:app"]
