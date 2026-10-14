"""
satc-idp CLI

    satc-idp serve [--host 127.0.0.1] [--port 5700]
    satc-idp users add <username> [--password-stdin]     비밀번호는 프롬프트나 stdin 으로만 받는다 (argv 금지)
    satc-idp users list | disable <username> | enable <username> | set-password <username> [--password-stdin]
    satc-idp clients add <client_id> --type confidential|public [--redirect-uri URI ...] [--scope S ...] [--grant G ...]
                         [--audience AUD ...]   (없으면 allowed_audiences 전체)
    satc-idp clients list | remove <client_id>
    satc-idp keys rotate | list

모든 명령은 -c config/idp.yaml (또는 SATC_IDP_CONFIG) 을 쓴다.
"""

import argparse
import getpass
import json
import logging
import os
import sys
import time

from .app import ALL_GRANTS, create_app, new_client_secret
from .config import load_config
from .db import Database
from .keys import KeyStore
from .security import hash_secret, is_loopback_redirect

DEFAULT_CONFIG = os.getenv("SATC_IDP_CONFIG", "config/idp.yaml")
MIN_PASSWORD_LENGTH = 12


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("비밀번호: ")
        if getpass.getpass("비밀번호 확인: ") != password:
            raise SystemExit("비밀번호가 일치하지 않습니다")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise SystemExit(f"비밀번호는 {MIN_PASSWORD_LENGTH}자 이상이어야 합니다")
    return password


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="satc-idp")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--host", default=os.getenv("IDP_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.getenv("IDP_PORT", "5700")))

    users = sub.add_parser("users").add_subparsers(dest="action", required=True)
    u_add = users.add_parser("add")
    u_add.add_argument("username")
    u_add.add_argument("--password-stdin", action="store_true")
    users.add_parser("list")
    for name in ("disable", "enable"):
        users.add_parser(name).add_argument("username")
    u_pw = users.add_parser("set-password")
    u_pw.add_argument("username")
    u_pw.add_argument("--password-stdin", action="store_true")

    clients = sub.add_parser("clients").add_subparsers(dest="action", required=True)
    c_add = clients.add_parser("add")
    c_add.add_argument("client_id")
    c_add.add_argument("--type", required=True, choices=["confidential", "public"])
    c_add.add_argument("--name")
    c_add.add_argument("--redirect-uri", action="append", default=[])
    c_add.add_argument("--scope", action="append", default=[])
    c_add.add_argument("--grant", action="append", default=[], choices=sorted(ALL_GRANTS))
    c_add.add_argument("--audience", action="append", default=[])
    clients.add_parser("list")
    clients.add_parser("remove").add_argument("client_id")

    keys = sub.add_parser("keys").add_subparsers(dest="action", required=True)
    keys.add_parser("rotate")
    keys.add_parser("list")

    args = parser.parse_args(argv)
    # DB·WAL·키·감사 로그를 모두 소유자만 읽을 수 있게 만든다
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        raise SystemExit(f"설정 파일이 없습니다: {args.config} (config/idp.example.yaml 참고)")

    if args.command == "serve":
        import uvicorn

        # X-Forwarded-For 는 앱의 ProxyHeadersMiddleware(forwarded_allow_ips) 만 처리한다. uvicorn 기본 처리는 끈다
        uvicorn.run(create_app(config), host=args.host, port=args.port, proxy_headers=False)
        return

    if args.command == "keys":
        store = KeyStore(config.resolve(config.keystore_dir), config.published_previous_keys)
        if args.action == "rotate":
            print(f"새 서명 키: {store.rotate()}")
        for entry in store.list():
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry["created_at"]))
            print(f"  {entry['kid']:<24} {entry['status']:<9} {created}")
        return

    db = Database(config.resolve(config.db_path))
    if args.command == "users":
        _users(db, args)
    else:
        _clients(db, config, args)


def _users(db: Database, args) -> None:
    if args.action == "add":
        if db.get_user_by_name(args.username):
            raise SystemExit("이미 있는 사용자입니다")
        user_id = db.add_user(args.username, hash_secret(_read_password(args.password_stdin)))
        print(f"사용자 추가: {args.username} ({user_id})")
    elif args.action == "list":
        for u in db.list_users():
            print(f"  {u['username']:<20} {'disabled' if u['disabled'] else 'active':<9} {u['id']}")
    elif args.action in ("disable", "enable"):
        if not db.set_user_disabled(args.username, args.action == "disable"):
            raise SystemExit("없는 사용자입니다")
        if args.action == "disable":
            db.revoke_user_tokens(db.get_user_by_name(args.username)["id"], "user_disabled")
        print(f"{args.username}: {args.action}d")
    elif args.action == "set-password":
        user = db.get_user_by_name(args.username)
        if user is None:
            raise SystemExit("없는 사용자입니다")
        db.set_password(args.username, hash_secret(_read_password(args.password_stdin)))
        # 비밀번호를 바꾸면 기존 refresh token 은 모두 폐기한다
        db.revoke_user_tokens(user["id"], "password_changed")
        print(f"{args.username}: 비밀번호 변경")


def _clients(db: Database, config, args) -> None:
    if args.action == "list":
        for c in db.list_clients():
            print(json.dumps(c, ensure_ascii=False))
        return
    if args.action == "remove":
        if not db.remove_client(args.client_id):
            raise SystemExit("없는 클라이언트입니다")
        print(f"클라이언트 삭제: {args.client_id}")
        return

    if db.get_client(args.client_id):
        raise SystemExit("이미 있는 client_id 입니다")
    scopes = args.scope or list(config.scopes)
    unknown = set(scopes) - set(config.scopes)
    if unknown:
        raise SystemExit(f"설정에 없는 scope: {sorted(unknown)}")
    if args.type == "confidential":
        grants = args.grant or ["client_credentials"]
    else:
        grants = args.grant or ["authorization_code", "refresh_token"]
        if "client_credentials" in grants:
            raise SystemExit("공개 클라이언트는 client_credentials 를 쓸 수 없습니다")
    if "authorization_code" in grants and not args.redirect_uri:
        raise SystemExit("authorization_code 를 쓰려면 --redirect-uri 가 필요합니다")
    for uri in args.redirect_uri:
        if "#" in uri or not (uri.startswith("https://") or is_loopback_redirect(uri)):
            raise SystemExit(f"redirect_uri 는 https 또는 loopback http 여야 합니다: {uri}")
    unknown_aud = set(args.audience) - set(config.allowed_audiences)
    if unknown_aud:
        raise SystemExit(f"설정의 allowed_audiences 에 없는 audience: {sorted(unknown_aud)}")

    secret = secret_hash = None
    if args.type == "confidential":
        secret, secret_hash = new_client_secret()
    db.add_client(args.client_id, args.type, secret_hash, args.redirect_uri, grants, scopes, "cli", name=args.name,
                  allowed_audiences=args.audience or None)
    print(f"클라이언트 추가: {args.client_id} ({args.type}, grants={','.join(grants)}, scopes={' '.join(scopes)})")
    if secret:
        print(f"client_secret: {secret}")
        print("이 값은 다시 볼 수 없습니다. 안전한 곳에 보관하세요.")


if __name__ == "__main__":
    main()
