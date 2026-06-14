from __future__ import annotations

import platform
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from oauth.creds import get_claude_client_id, get_codex_client_id
from oauth.pkce import generate_code_challenge, generate_code_verifier, generate_state

_CLAUDE_CLI_VERSION = "2.1.158"
_STAINLESS_PACKAGE_VERSION = "0.81.0"
_STAINLESS_NODE_VERSION = "v22.11.0"

_PROVIDERS: dict[str, dict] = {
    "claude": {
        "name": "Claude Code",
        "client_id_fn": get_claude_client_id,
        "authorize_url": "https://claude.ai/oauth/authorize",
        "token_url": "https://api.anthropic.com/v1/oauth/token",
        "scopes": "user:profile user:inference user:sessions:claude_code user:mcp_servers",
        "flow_type": "manual",
        "redirect_uri": "https://platform.claude.com/oauth/code/callback",
        "token_content_type": "application/json",
        "extra_auth_params": {"code": "true"},
    },
    "codex": {
        "name": "OpenAI Codex",
        "client_id_fn": get_codex_client_id,
        "authorize_url": "https://auth.openai.com/oauth/authorize",
        "token_url": "https://auth.openai.com/oauth/token",
        "scopes": "openid profile email offline_access",
        "flow_type": "localhost",
        "fixed_port": 1455,
        "callback_path": "/auth/callback",
        "token_content_type": "application/x-www-form-urlencoded",
        "extra_auth_params": {
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
            "originator": "codex_cli_rs",
            "prompt": "login",
        },
    },
}

_SUCCESS_HTML = b"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>necli</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;
height:100vh;margin:0;background:#111}.box{text-align:center;padding:2rem;background:#1e1e1e;
border-radius:8px;color:#fff}.ok{color:#4ade80;font-size:3rem}p{color:#aaa}</style></head>
<body><div class="box"><div class="ok">&#10003;</div><h2>Authorized</h2>
<p>Return to terminal. This tab will close.</p></div>
<script>setTimeout(()=>window.close(),2000)</script></body></html>"""


def get_provider_names() -> list[str]:
    return list(_PROVIDERS.keys())


def get_provider_display_name(provider: str) -> str:
    return _PROVIDERS[provider]["name"]


def get_provider_flow_type(provider: str) -> str:
    return _PROVIDERS[provider].get("flow_type", "localhost")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stainless_arch() -> str:
    m = (platform.machine() or "").lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m in ("i386", "i686"):
        return "ia32"
    return m or "unknown"


def _stainless_os() -> str:
    return {"Darwin": "MacOS", "Linux": "Linux", "Windows": "Windows"}.get(
        platform.system(), platform.system() or "Unknown"
    )


def _claude_spoof_headers() -> dict[str, str]:
    return {
        "anthropic-dangerous-direct-browser-access": "true",
        "x-stainless-arch": _stainless_arch(),
        "x-stainless-lang": "js",
        "x-stainless-os": _stainless_os(),
        "x-stainless-package-version": _STAINLESS_PACKAGE_VERSION,
        "x-stainless-retry-count": "0",
        "x-stainless-runtime": "node",
        "x-stainless-runtime-version": _STAINLESS_NODE_VERSION,
        "x-stainless-timeout": "600",
    }


def _claude_bootstrap(access_token: str) -> dict:
    try:
        r = httpx.get(
            "https://api.anthropic.com/api/claude_cli/bootstrap",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "User-Agent": f"claude-cli/{_CLAUDE_CLI_VERSION} (external, cli)",
                "anthropic-beta": "oauth-2025-04-20",
            },
            timeout=10,
        )
        if r.is_success:
            acct = r.json().get("oauth_account") or {}
            return {
                k: acct.get(k)
                for k in (
                    "account_uuid",
                    "account_email",
                    "organization_uuid",
                    "organization_name",
                    "organization_type",
                    "organization_rate_limit_tier",
                )
            }
    except Exception:
        pass
    return {}


def prepare_oauth(provider_name: str) -> dict:
    cfg = _PROVIDERS.get(provider_name)
    if not cfg:
        raise ValueError(f"Unknown OAuth provider: {provider_name!r}")

    client_id = cfg["client_id_fn"]()
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = generate_state()
    flow_type = cfg.get("flow_type", "localhost")

    if flow_type == "manual":
        redirect_uri = cfg["redirect_uri"]
        port = None
    else:
        port = cfg.get("fixed_port") or _free_port()
        redirect_uri = f"http://localhost:{port}{cfg['callback_path']}"

    auth_params: dict[str, str] = {
        **cfg.get("extra_auth_params", {}),
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": cfg["scopes"],
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }

    return {
        "provider_name": provider_name,
        "auth_url": f"{cfg['authorize_url']}?{urlencode(auth_params)}",
        "flow_type": flow_type,
        "_state": state,
        "_code_verifier": code_verifier,
        "_redirect_uri": redirect_uri,
        "_cfg": cfg,
        "_client_id": client_id,
        "_port": port,
    }


def run_localhost_callback(session: dict, timeout: int = 120) -> str:
    port = session["_port"]
    result: dict = {"code": None, "error": None}
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if done.is_set():
                return
            qs = parse_qs(urlparse(self.path).query)
            if "code" in qs:
                result["code"] = qs["code"][0]
                body = _SUCCESS_HTML
                done.set()
            elif "error" in qs:
                result["error"] = qs.get("error", ["unknown"])[0]
                desc = qs.get("error_description", [""])[0]
                body = f"<html><body><p>Error: {result['error']}: {desc}</p></body></html>".encode()
                done.set()
            else:
                body = b"<html><body><p>Waiting...</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", port), _Handler)
    server.timeout = 1.0

    def _serve() -> None:
        while not done.is_set():
            server.handle_request()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    done.wait(timeout=timeout)
    server.server_close()
    t.join(timeout=2)

    if result["error"]:
        raise ValueError(f"OAuth error: {result['error']}")
    if not result["code"]:
        raise TimeoutError("OAuth timed out — browser flow not completed")

    return result["code"]


def exchange_oauth_code(session: dict, raw_code: str) -> dict:
    cfg = session["_cfg"]
    client_id = session["_client_id"]
    code_verifier = session["_code_verifier"]
    state = session["_state"]
    redirect_uri = session["_redirect_uri"]
    provider_name = session["provider_name"]

    auth_code = raw_code
    returned_state = state
    if "#" in raw_code:
        auth_code, _, frag = raw_code.partition("#")
        if frag:
            returned_state = frag

    content_type: str = cfg["token_content_type"]
    if content_type == "application/json":
        resp = httpx.post(
            cfg["token_url"],
            json={
                "code": auth_code,
                "state": returned_state,
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={
                "Content-Type": content_type,
                "Accept": "application/json",
                "anthropic-beta": "oauth-2025-04-20",
                "User-Agent": f"claude-cli/{_CLAUDE_CLI_VERSION} (external, cli)",
                **_claude_spoof_headers(),
            },
            timeout=30,
        )
    else:
        resp = httpx.post(
            cfg["token_url"],
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": content_type, "Accept": "application/json"},
            timeout=30,
        )

    if not resp.is_success:
        raise ValueError(f"Token exchange failed ({resp.status_code}): {resp.text}")

    tokens = resp.json()
    out = {
        "provider": provider_name,
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "expires_in": tokens.get("expires_in"),
        "scope": tokens.get("scope") or cfg["scopes"],
        "id_token": tokens.get("id_token"),
    }

    if provider_name == "claude" and out.get("access_token"):
        out.update(_claude_bootstrap(out["access_token"]))

    return out
