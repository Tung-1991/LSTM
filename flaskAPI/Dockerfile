FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Chạy Gunicorn trực tiếp, không cần start.sh
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "alert:app"]
