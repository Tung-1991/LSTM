#!/bin/bash

# Kiểm tra thư mục Git
if [ ! -d .git ]; then
  echo "⚠️  Thư mục này không phải là Git repo!"
  exit 1
fi

# Nhập commit message
read -p "🔧 Nhập commit message: " msg

# Đẩy code
git add .
git commit -m "$msg"
git push -u origin main
