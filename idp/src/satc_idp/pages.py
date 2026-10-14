"""
HTML 화면 (로그인, 오류). 외부 리소스·스크립트 없이 인라인 스타일만 쓰고, 출력 값은 모두 escape 한다.
"""

from html import escape
from typing import List, Optional

from starlette.responses import HTMLResponse

# 스크립트·외부 리소스 금지, 다른 사이트의 iframe 삽입 금지.
# form-action 은 넣지 않는다: 로그인 POST 뒤 클라이언트 redirect_uri 로 보내는 302 까지 브라우저가 막는다.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

_STYLE = """
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f5f6f8;color:#1f2329;margin:0}
main{max-width:360px;margin:12vh auto;background:#fff;padding:28px 28px 20px;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:18px;margin:0 0 6px}p{font-size:13px;color:#5b6270;margin:0 0 16px}
label{display:block;font-size:13px;margin:12px 0 4px}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfd3da;border-radius:6px;font-size:14px}
button{margin-top:18px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f5bd3;color:#fff;font-size:14px;cursor:pointer}
.err{background:#fdecec;color:#a42121;padding:8px 10px;border-radius:6px;font-size:13px;margin-bottom:8px}
code{background:#eef0f3;padding:1px 4px;border-radius:4px}
.warn{color:#a42121;font-weight:600}
"""


def _page(title: str, body: str, status: int) -> HTMLResponse:
    html = (
        "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body><main>{body}</main></body></html>"
    )
    return HTMLResponse(html, status_code=status, headers=SECURITY_HEADERS)


def login_page(request_id: str, csrf_token: str, client_name: str, scopes: List[str],
               error: Optional[str] = None, username: str = "", status: int = 200,
               unverified: bool = False) -> HTMLResponse:
    err = f"<div class=\"err\">{escape(error)}</div>" if error else ""
    scope_text = ", ".join(f"<code>{escape(s)}</code>" for s in scopes) or "없음"
    # 동적 등록(DCR) 클라이언트는 이름을 스스로 정하므로 검증되지 않았다고 표시한다
    label = " <span class=\"warn\">(미검증 클라이언트)</span>" if unverified else ""
    body = (
        "<h1>로그인</h1>"
        f"<p><b>{escape(client_name)}</b>{label} 이(가) 접근을 요청합니다. 권한: {scope_text}</p>"
        f"{err}"
        "<form method=\"post\" action=\"/authorize\" autocomplete=\"on\">"
        f"<input type=\"hidden\" name=\"request_id\" value=\"{escape(request_id)}\">"
        f"<input type=\"hidden\" name=\"csrf_token\" value=\"{escape(csrf_token)}\">"
        "<label for=\"username\">아이디</label>"
        f"<input id=\"username\" name=\"username\" type=\"text\" value=\"{escape(username)}\" required autofocus>"
        "<label for=\"password\">비밀번호</label>"
        "<input id=\"password\" name=\"password\" type=\"password\" required>"
        "<button type=\"submit\">로그인</button>"
        "</form>"
    )
    return _page("로그인", body, status)


def error_page(message: str, status: int = 400) -> HTMLResponse:
    body = f"<h1>요청을 처리할 수 없습니다</h1><p>{escape(message)}</p>"
    return _page("오류", body, status)
