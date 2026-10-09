"""HTML-отчёт: один самодостаточный файл (скриншоты вшиты), открывается в любом браузере."""
from __future__ import annotations

import base64
import io
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import STATUS_ORDER, Status

try:
    from PIL import Image
    HAVE_PIL = True
except ImportError:  # pragma: no cover
    HAVE_PIL = False

TEMPLATE_DIR = Path(__file__).parent

STATUS_LABEL = {
    "PASS": "OK", "WARN": "Внимание", "FAIL": "Провал", "INFO": "Инфо",
    "SKIP": "Пропуск", "FLAKY": "Нестабилен", "BLOCKED": "Заблокирован",
}

SECTIONS = [
    ("static", "Статический анализ APK", "Проверки файла сборки без запуска."),
    ("diff", "Изменения относительно прошлой сборки", "Что поменялось с предыдущей проверенной версии этого пакета."),
    ("device", "Базовая проверка на устройстве", "Установка, старт, стабильность — работает без написанных тестов."),
    ("maestro", "Сценарии (Maestro)", "Smoke-флоу из .maestro/. Упавшие тесты перезапускаются для выявления нестабильных."),
]


def _image_data_uri(path: Path, width: int) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if HAVE_PIL and path.suffix.lower() in (".png", ".jpg", ".jpeg"):
        try:
            img = Image.open(io.BytesIO(raw))
            img = img.convert("RGB")
            if img.width > width * 2:
                h = int(img.height * (width * 2) / img.width)
                img = img.resize((width * 2, h))
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=72, optimize=True)
            return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
        except Exception:  # noqa: BLE001
            pass
    if len(raw) > 1_500_000:
        return None
    mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    return f"data:{mime};base64," + base64.b64encode(raw).decode()


def _section_of(check: dict) -> str:
    if check["category"] == "static" and check["id"].startswith("D"):
        return "diff"
    return check["category"]


def build_report(summary: dict[str, Any], run_dir: Path, cfg) -> Path:
    rc = cfg["report"]
    embed = bool(rc.get("embed_images", True))
    width = int(rc.get("image_width", 360))

    images: dict[str, str] = {}
    gallery: list[dict] = []
    for c in summary["checks"]:
        for ev in c.get("evidence", []):
            if Path(ev).suffix.lower() not in (".png", ".jpg", ".jpeg", ".gif"):
                continue
            if ev not in images:
                uri = _image_data_uri(run_dir / ev, width) if embed else None
                images[ev] = uri or ev
                gallery.append({"src": images[ev], "path": ev, "caption": f"{c['id']} · {c['title']}",
                                "status": c["status"]})

    sections = []
    for key, title, hint in SECTIONS:
        rows = [c for c in summary["checks"] if _section_of(c) == key]
        if not rows:
            continue
        rows.sort(key=lambda c: (STATUS_ORDER[Status(c["status"])], c["id"]) if key != "maestro"
                  else (STATUS_ORDER[Status(c["status"])], c.get("priority") or "P9", c["id"]))
        counts: dict[str, int] = {}
        for c in rows:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        sections.append({"key": key, "title": title, "hint": hint, "rows": rows, "counts": counts})

    history = summary.get("history") or []
    max_cs = max([h["cold_start_ms"] for h in history if isinstance(h.get("cold_start_ms"), (int, float))] or [0])

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html", "j2"]))
    env.filters["status_label"] = lambda s: STATUS_LABEL.get(s, s)
    html = env.get_template("template.html.j2").render(
        s=summary, apk=summary["apk"], sections=sections, images=images, gallery=gallery,
        history=history, max_cs=max_cs, status_label=STATUS_LABEL,
    )
    path = run_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path
