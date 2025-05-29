#FROM tensorflow/tensorflow:2.15.0-gpu
FROM tensorflow/tensorflow:2.15.0

# Cài tzdata để nhận timezone từ host
RUN apt-get update && apt-get install -y tzdata

# Đặt múi giờ mặc định trong container là GMT+7
ENV TZ=Asia/Ho_Chi_Minh

# Đặt thư mục làm việc
WORKDIR /app

# Copy mã nguồn
COPY . /app

# Cài thư viện cần thiết
RUN pip install --no-cache-dir -r requirements.txt

# Chạy script chính
CMD ["python", "main.py"]
