from __future__ import annotations

import sys
import webbrowser

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from config.themes import t
from config.i18n import t as _
from ui.menu import select_menu

console = Console()


def oauth_interactive() -> None:
    accent = t("accent")
    success = t("success")
    error_color = t("error")

    items = [
        {"label": "Claude Code  (Anthropic)", "hint": "claude.ai → api.anthropic.com"},
        {"label": "OpenAI Codex (ChatGPT)",   "hint": "auth.openai.com → api.openai.com"},
    ]
    provider_keys = ["claude", "codex"]

    console.print()
    choice = select_menu(items, title=_("oauth.pick_provider"))
    if choice is None:
        return

    provider = provider_keys[choice]

    from oauth.flow import get_provider_display_name

    display = get_provider_display_name(provider)
    console.print()

    session = _show_link_and_open(provider)
    if session is None:
        return

    if session["flow_type"] == "manual":
        tokens = _manual_paste_flow(session, accent, error_color)
    else:
        tokens = _localhost_wait_flow(session, accent, error_color)

    if tokens is None:
        return

    if not tokens.get("access_token"):
        console.print(f"  [{error_color}]{_('oauth.no_token')}[/{error_color}]")
        return

    import config
    config.set_oauth_token(provider, tokens)
    _try_activate_provider(provider)
    console.print(f"  [{success}]✓[/{success}] {_('oauth.saved', provider=display)}")
    console.print()


def _show_link_and_open(provider: str) -> dict | None:
    from oauth.flow import prepare_oauth

    console.print("  🔗 [dim]Link:  Loading...[/dim]")
    try:
        session = prepare_oauth(provider)
    except Exception as e:
        sys.stdout.write("\x1b[1A\r\x1b[2K")
        sys.stdout.flush()
        console.print(f"  [red]Failed to prepare OAuth: {e}[/red]")
        return None

    sys.stdout.write("\x1b[1A\r\x1b[2K")
    sys.stdout.flush()
    url = session["auth_url"]
    console.print(f"  🔗 [dim]Link:[/dim]  {url}")
    console.print()
    webbrowser.open(url)
    return session


def _manual_paste_flow(session: dict, accent: str, error_color: str) -> dict | None:
    from oauth.flow import exchange_oauth_code

    body = Text()
    body.append("Paste Authorization Code\n\n", style=f"bold {accent}")
    body.append("Complete sign-in in your browser. You will be redirected to\n", style="dim")
    body.append("platform.claude.com/oauth/code/callback\n", style="bold")
    body.append("Copy the code shown on that page and paste it below.\n\n", style="dim")
    body.append("Format: ", style="dim")
    body.append("code#state", style="italic dim")

    console.print(Panel(body, border_style=accent, padding=(1, 2)))
    console.print()

    try:
        raw = console.input("  Code: ").strip()
    except (KeyboardInterrupt, EOFError):
        console.print()
        return None

    if not raw:
        console.print(f"  [{error_color}]No code entered.[/{error_color}]")
        return None

    console.print("  [dim]Exchanging code...[/dim]")
    try:
        return exchange_oauth_code(session, raw)
    except KeyboardInterrupt:
        console.print()
        return None
    except Exception as e:
        console.print(f"  [{error_color}]{_('oauth.error', msg=str(e))}[/{error_color}]")
        return None


def _localhost_wait_flow(session: dict, accent: str, error_color: str) -> dict | None:
    from oauth.flow import run_localhost_callback, exchange_oauth_code

    body = Text()
    body.append("Waiting for browser callback\n\n", style=f"bold {accent}")
    body.append("Complete authorization in your browser.\n", style="dim")
    body.append("Ctrl+C to cancel", style="dim")
    console.print(Panel(body, border_style=accent, padding=(1, 2)))
    console.print()

    try:
        raw_code = run_localhost_callback(session)
        return exchange_oauth_code(session, raw_code)
    except KeyboardInterrupt:
        console.print()
        return None
    except TimeoutError:
        console.print(f"  [{error_color}]{_('oauth.timeout')}[/{error_color}]")
        return None
    except Exception as e:
        console.print(f"  [{error_color}]{_('oauth.error', msg=str(e))}[/{error_color}]")
        return None


def _try_activate_provider(oauth_provider: str) -> None:
    from apis.config import list_api_configs
    from apis.registry import get_definition

    pid_map = {"claude": "anthropic", "codex": "openai"}
    target_pid = pid_map.get(oauth_provider)
    if not target_pid:
        return

    cfgs = list_api_configs()
    for cfg in cfgs:
        pid = cfg.get("id") if isinstance(cfg, dict) else None
        if pid == target_pid:
            defn = get_definition(pid)
            if defn:
                import config
                model_id = defn.default_model or (defn.models[0].id if defn.models else "")
                if model_id:
                    config.set_active_api(pid)
                    config.set_active_api_model(model_id)
            return
