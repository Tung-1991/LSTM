FROM python:3.10-slim

# Cài tzdata để dùng được timezone từ host
RUN apt-get update && apt-get install -y tzdata && rm -rf /var/lib/apt/lists/*

# Đặt timezone cố định bên trong container (phòng trường hợp không mount volume host)
ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "alert.py"]
