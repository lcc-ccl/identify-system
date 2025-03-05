#!/bin/bash

# 停止并删除已存在的容器（如果存在）
docker stop identity-system 2>/dev/null || true
docker rm identity-system 2>/dev/null || true

# 构建 Docker 镜像
echo "正在构建 Docker 镜像..."
docker build -t identity-system .

# 运行容器
echo "正在启动容器..."
docker run -d \
    --name identity-system \
    -p 5000:5000 \
    -v $(pwd)/instance:/app/instance \
    identity-system

echo "系统已成功部署！"
echo "访问 http://localhost:5000 以使用系统" 