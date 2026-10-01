FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /srv

# 零第三方依赖：只需拷贝源码与一次性 verify 资产
COPY app ./app
COPY tests ./tests
COPY verify.py ./verify.py

EXPOSE 8080

# 简单健康检查（运行时也可用 GET /health）
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/health'%os.environ.get('PORT','8080'),timeout=3)" || exit 1

# 可配置宿主端口由 Compose 映射与 PORT 决定
CMD ["python", "-m", "app.server"]
