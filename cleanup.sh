#!/bin/bash

# Dừng và xóa các container đang chạy
docker-compose down

# Xóa các file và thư mục được tạo ra trong quá trình chạy
echo "Cleaning up generated files..."
rm -rf ./app/models/*
rm -rf ./app/outputs/*
rm -rf ./flaskAPI/ai_suggestions/*
rm -rf ./flaskAPI/__pycache__
rm -rf ./logWatcher/archived_logs/*
rm -rf ./sre_agent/logs/*

# Xóa trắng nội dung file log nhưng giữ lại file
echo "Clearing log files..."
truncate -s 0 ./app/monitoring_log.log
truncate -s 0 ./app/cooldown_cache.json
truncate -s 0 ./flaskAPI/flask_alert.log
#truncate -s 0 ./flaskAPI/_gapo_preview.md
truncate -s 0 ./logWatcher/log_watcher_cooldown.json
# Dọn dẹp Docker
echo "Pruning Docker system..."
docker system prune -f
docker builder prune -f
docker system prune -f
docker system prune -a --volumes -f
docker builder prune -a -f

echo "Cleanup complete."
