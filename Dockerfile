# satc-mcp-gateway (streamable-http)
#
# 설정은 이미지에 넣지 않고 /app/config 에 마운트한다 (config/gateway.yaml, config/registry/*.yaml).
# HTTP 를 0.0.0.0 으로 열기 때문에 auth.mode 를 static_tokens 또는 jwt 로 설정해야 기동한다.

FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:0.7.21 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 의존성 레이어를 먼저 만든다 (소스만 바뀌면 재사용)
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN uv sync --frozen --no-dev

RUN useradd --system --uid 10001 --no-create-home gateway \
    && mkdir -p /app/config /app/logs \
    && chown gateway /app/logs

USER gateway

# OPENSSL_armcap=0: Apple M4 의 Docker(arm64 VM) 에서 OpenSSL 이 CPU 기능(SVE)을 잘못 감지해
# cryptography import 시 SIGILL(Illegal instruction, exit 132) 로 죽는 문제를 피한다.
# x86 에서는 무시되고, ARM 서버에서는 OpenSSL 하드웨어 가속이 꺼진다. 필요하면 -e OPENSSL_armcap= 로 끈다.
ENV PATH="/app/.venv/bin:$PATH" \
    SATC_GATEWAY_CONFIG=/app/config/gateway.yaml \
    OPENSSL_armcap=0

EXPOSE 5600

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5600/health', timeout=3)"

CMD ["satc-mcp-gateway", "serve", "--transport", "http", "--host", "0.0.0.0", "--port", "5600"]
