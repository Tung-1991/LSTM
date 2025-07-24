FROM python:3.10-slim

# Cài đặt và cấu hình múi giờ GMT+7
RUN apt-get update && apt-get install -y tzdata
ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /flaskAPI

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "alert:app"]
