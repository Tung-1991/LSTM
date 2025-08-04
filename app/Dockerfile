#FROM tensorflow/tensorflow:2.15.0-gpu
FROM tensorflow/tensorflow:2.15.0

# Fix lỗi NVIDIA repo: xóa file cuda.list nếu có
RUN rm -f /etc/apt/sources.list.d/cuda* && \
    apt-get update && apt-get install -y tzdata

ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py"]
