FROM python:3.10-slim

# Cài tzdata và openssh-client để dùng timezone + SSH ra ngoài
RUN apt-get update && apt-get install -y tzdata openssh-client && rm -rf /var/lib/apt/lists/*

# Đặt timezone cố định bên trong container
ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "alert.py"]
