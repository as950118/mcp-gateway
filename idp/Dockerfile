# satc-idp (OAuth 2.1 인가 서버)
#
# 설정은 이미지에 넣지 않고 /app/config 에 마운트한다 (config/idp.yaml).
# DB·서명 키·감사 로그는 /app/data 볼륨에 쌓인다 (예시 설정의 ../data 경로가 /app/data 를 가리킨다).
# 운영에서는 issuer 를 https 로 두고 TLS 리버스 프록시 뒤에서 실행한다 (forwarded_allow_ips 에 프록시 IP).

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

RUN useradd --system --uid 10002 --no-create-home idp \
    && mkdir -p /app/config /app/data \
    && chown idp /app/data \
    && chmod 700 /app/data

USER idp

# OPENSSL_armcap=0: Apple M4 의 Docker(arm64 VM) 에서 OpenSSL 이 CPU 기능을 잘못 감지해
# cryptography import 시 SIGILL(exit 132) 로 죽는 문제를 피한다. x86 에서는 무시된다.
ENV PATH="/app/.venv/bin:$PATH" \
    SATC_IDP_CONFIG=/app/config/idp.yaml \
    OPENSSL_armcap=0

VOLUME ["/app/data"]
EXPOSE 5700

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5700/health', timeout=3)"

CMD ["satc-idp", "serve", "--host", "0.0.0.0", "--port", "5700"]
