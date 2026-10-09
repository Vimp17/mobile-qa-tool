"""История прогонов: папка qa_runs/, поиск прошлой сборки, общий CSV."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

CSV_FIELDS = [
    "run_id", "date", "project", "environment", "package", "version_name", "version_code", "build_type",
    "verdict", "static_fail", "static_warn", "device", "cold_start_ms", "memory_mb", "crashes",
    "tests_total", "tests_passed", "tests_failed", "tests_flaky", "apk_size_mb", "sha256", "report",
]


def load_runs(runs_dir: Path) -> list[dict[str, Any]]:
    runs = []
    if not runs_dir.is_dir():
        return runs
    for f in runs_dir.glob("*/summary.json"):
        try:
            runs.append(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    runs.sort(key=lambda r: r.get("timestamp", ""))
    return runs


def previous_build(runs_dir: Path, package: str, exclude_run: str = "", sha256: str = "") -> dict | None:
    """Последний прогон этого пакета с другой сборкой (по sha256)."""
    for r in reversed(load_runs(runs_dir)):
        apk = r.get("apk") or {}
        if r.get("run_id") == exclude_run or apk.get("package") != package:
            continue
        if sha256 and apk.get("sha256") == sha256:
            continue
        return apk
    return None


def history_rows(runs_dir: Path, package: str, limit: int = 15) -> list[dict]:
    rows = []
    for r in load_runs(runs_dir):
        if (r.get("apk") or {}).get("package") == package:
            rows.append(summary_row(r))
    return rows[-limit:]


def summary_row(s: dict[str, Any]) -> dict[str, Any]:
    apk = s.get("apk") or {}
    t = s.get("totals") or {}
    m = s.get("metrics") or {}
    return {
        "run_id": s.get("run_id", ""),
        "date": s.get("timestamp", "")[:19].replace("T", " "),
        "project": s.get("project", ""),
        "environment": s.get("environment", ""),
        "package": apk.get("package", ""),
        "version_name": apk.get("version_name", ""),
        "version_code": apk.get("version_code", ""),
        "build_type": s.get("build_type", ""),
        "verdict": s.get("verdict_title", ""),
        "static_fail": t.get("static_fail", 0),
        "static_warn": t.get("static_warn", 0),
        "device": (s.get("device") or {}).get("title", "не запускалось"),
        "cold_start_ms": m.get("cold_start_ms", ""),
        "memory_mb": m.get("memory_pss_mb", ""),
        "crashes": len(s.get("crashes") or []),
        "tests_total": t.get("tests_total", 0),
        "tests_passed": t.get("tests_passed", 0),
        "tests_failed": t.get("tests_failed", 0),
        "tests_flaky": t.get("tests_flaky", 0),
        "apk_size_mb": apk.get("size_mb", ""),
        "sha256": apk.get("sha256", "")[:16],
        "report": s.get("report_path", ""),
        "_verdict": s.get("verdict", ""),
    }


def append_csv(runs_dir: Path, summary: dict[str, Any]) -> Path:
    path = runs_dir / "history.csv"
    new = not path.exists()
    row = summary_row(summary)
    # utf-8-sig — чтобы Excel на Windows открыл кириллицу без «кракозябр»
    with path.open("a", encoding="utf-8-sig" if new else "utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, delimiter=";", extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow(row)
    return path
