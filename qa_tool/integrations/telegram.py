"""Короткое уведомление в Telegram + HTML-отчёт файлом."""
from __future__ import annotations

from pathlib import Path
from typing import Any

EMOJI = {"GO": "✅", "GO_WITH_REMARKS": "⚠️", "NO_GO": "⛔"}


def build_message(summary: dict[str, Any]) -> str:
    apk = summary["apk"]
    t = summary["totals"]
    m = summary.get("metrics", {})
    lines = [
        f"{EMOJI.get(summary['verdict'], '')} {summary['verdict_title']}",
        f"📱 {apk.get('label') or apk['package']} {apk['version_name']} ({apk['version_code']}) · {summary['environment']}",
        "",
        f"Статика: провалов {t['static_fail']}, предупреждений {t['static_warn']}",
    ]
    if summary.get("device"):
        lines.append(f"Устройство: {summary['device']['title']}")
        if "cold_start_ms" in m:
            lines.append(f"Холодный старт: {m['cold_start_ms']} мс")
        lines.append(f"Крэши/ANR: {len(summary.get('crashes', []))}")
    else:
        lines.append("Устройство: не запускалось")
    if t["tests_total"]:
        lines.append(f"Тесты: {t['tests_passed']}/{t['tests_total']}" + (f", нестабильных {t['tests_flaky']}" if t["tests_flaky"] else ""))
    reasons = summary.get("reasons", [])
    if reasons:
        lines += ["", "Причины:"] + [f"• {r['id']} {r['title']}" for r in reasons[:6]]
        if len(reasons) > 6:
            lines.append(f"…и ещё {len(reasons) - 6}")
    return "\n".join(lines)


def send_telegram(summary: dict[str, Any], report: Path | None, cfg) -> None:
    import requests

    tc = cfg["telegram"]
    token, chat = tc.get("bot_token"), tc.get("chat_id")
    if not token or not chat:
        raise RuntimeError("Нужны TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID (в .env или qa.yaml → telegram)")
    base = f"https://api.telegram.org/bot{token}"
    r = requests.post(f"{base}/sendMessage", json={"chat_id": chat, "text": build_message(summary)}, timeout=20)
    r.raise_for_status()
    if report and report.exists() and tc.get("send_report_file", True):
        with report.open("rb") as f:
            name = f"qa_{summary['apk']['package']}_{summary['apk']['version_name']}.html"
            r = requests.post(f"{base}/sendDocument", data={"chat_id": chat, "caption": "HTML-отчёт"},
                              files={"document": (name, f, "text/html")}, timeout=60)
            r.raise_for_status()
