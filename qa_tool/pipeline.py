"""Оркестратор: APK → статика → устройство (+Maestro) → вердикт → отчёт → интеграции."""
from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .apk.apk import ApkInfo, analyze_apk
from .config import Config
from .history import append_csv, history_rows, previous_build
from .models import CheckResult, Status
from .report.html import build_report
from .static_checks import run_static_checks
from .verdict import compute_verdict


@dataclass
class RunOptions:
    device: str | None = None
    skip_device: bool = False
    skip_maestro: bool = False
    no_monkey: bool = False
    expect_version: str | None = None
    sheets: bool | None = None      # None = как в конфиге
    telegram: bool | None = None


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "").strip("_")[:60] or "app"


def new_run_dir(runs_dir: Path, apk: ApkInfo) -> tuple[str, Path]:
    run_id = f"{datetime.now():%Y%m%d-%H%M%S}_{_slug(apk.package)}_{_slug(apk.version_name)}"
    d = runs_dir / run_id
    n = 1
    while d.exists():
        n += 1
        d = runs_dir / f"{run_id}-{n}"
    d.mkdir(parents=True)
    return d.name, d


def totals(checks: list[CheckResult]) -> dict[str, int]:
    st = [c for c in checks if c.category == "static"]
    tests = [c for c in checks if c.category == "maestro" and c.status != Status.SKIP]
    return {
        "static_total": len(st),
        "static_fail": sum(c.status == Status.FAIL for c in st),
        "static_warn": sum(c.status == Status.WARN for c in st),
        "static_pass": sum(c.status == Status.PASS for c in st),
        "device_fail": sum(c.status in (Status.FAIL,) for c in checks if c.category == "device"),
        "tests_total": len(tests),
        "tests_passed": sum(c.status in (Status.PASS, Status.FLAKY) for c in tests),
        "tests_failed": sum(c.status == Status.FAIL for c in tests),
        "tests_flaky": sum(c.status == Status.FLAKY for c in tests),
        "tests_blocked": sum(c.status == Status.BLOCKED for c in tests),
    }


def write_junit_all(summary: dict[str, Any], path: Path) -> None:
    """Все проверки в одном JUnit — чтобы CI (GitLab/Jenkins) показывал их как тесты."""
    suites = ET.Element("testsuites", name=f"qa-{summary['apk']['package']}")
    for cat in ("static", "device", "maestro"):
        cs = [c for c in summary["checks"] if c["category"] == cat]
        if not cs:
            continue
        suite = ET.SubElement(suites, "testsuite", name=cat, tests=str(len(cs)),
                              failures=str(sum(c["status"] == "FAIL" for c in cs)),
                              skipped=str(sum(c["status"] in ("SKIP", "BLOCKED") for c in cs)))
        for c in cs:
            tc = ET.SubElement(suite, "testcase", classname=cat, name=f"{c['id']} {c['title']}",
                               time=str(c.get("duration_sec") or 0))
            if c["status"] == "FAIL":
                ET.SubElement(tc, "failure", message=c["details"][:500]).text = "\n".join(c.get("items", []))
            elif c["status"] in ("SKIP", "BLOCKED"):
                ET.SubElement(tc, "skipped", message=c["details"][:500])
            elif c["status"] in ("WARN", "FLAKY"):
                ET.SubElement(tc, "system-out").text = f"{c['status']}: {c['details']}"
    ET.ElementTree(suites).write(path, encoding="utf-8", xml_declaration=True)


def run_check(apk_path: str | Path, cfg: Config, opts: RunOptions | None = None,
              log: Callable[[str], None] = print, device_runner=None) -> dict[str, Any]:
    """Полный цикл проверки. device_runner — для тестов/демо (подмена работы с устройством)."""
    opts = opts or RunOptions()
    started = time.time()
    runs_dir = cfg.resolve(cfg.get_path("paths.runs_dir", "qa_runs"))
    runs_dir.mkdir(parents=True, exist_ok=True)

    log(f"▶ Анализ APK: {apk_path}")
    apk = analyze_apk(apk_path)
    log(f"  {apk.package} {apk.version_name} ({apk.version_code}), {apk.size_mb} МБ")
    run_id, run_dir = new_run_dir(runs_dir, apk)
    (run_dir / "apk_info.json").write_text(json.dumps(apk.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    prev = previous_build(runs_dir, apk.package, exclude_run=run_id, sha256=apk.sha256)
    checks = run_static_checks(apk, cfg, prev, opts.expect_version)
    st_fail = sum(c.status == Status.FAIL for c in checks)
    log(f"  статика: {len(checks)} проверок, провалов {st_fail}")

    device_stage = None
    if not opts.skip_device and cfg.get_path("device.enabled", True):
        log("▶ Проверка на устройстве")
        if device_runner is not None:
            device_stage = device_runner(apk, cfg, run_dir, opts)
        else:
            from .device.smoke import run_device_stage
            from .maestro import run_maestro

            between = None
            if not opts.skip_maestro and cfg.get_path("maestro.enabled", True):
                def between(adb, dev):  # noqa: E306
                    return run_maestro(cfg, run_dir, apk.package, dev.serial, log=log)
            device_stage = run_device_stage(apk, cfg, run_dir, serial=opts.device, between=between,
                                            monkey=not opts.no_monkey, log=log)
        checks.extend(device_stage.checks)
        if device_stage.blocked_reason:
            log(f"  ⚠ {device_stage.blocked_reason}")
    else:
        checks.append(CheckResult("DV00", "Устройство", Status.SKIP, "Проверка на устройстве отключена (--static/--skip-device).",
                                  category="device"))

    device_ran = bool(device_stage and device_stage.device and not device_stage.blocked_reason)
    verdict, reasons = compute_verdict(checks, cfg, device_ran)

    dev = device_stage.device if device_stage else None
    summary: dict[str, Any] = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tool_version": __version__,
        "project": cfg.get_path("project.name"),
        "environment": cfg.get_path("project.environment"),
        "build_type": cfg.get_path("project.build_type"),
        "apk": apk.to_dict(),
        "prev_build": ({k: prev.get(k) for k in ("version_name", "version_code", "size_mb", "sha256")} if prev else None),
        "device": ({**asdict(dev), "title": dev.title} if dev else None),
        "metrics": device_stage.metrics if device_stage else {},
        "crashes": [c.to_dict() for c in device_stage.crashes] if device_stage else [],
        "logcat_file": device_stage.logcat_file if device_stage else "",
        "checks": [c.to_dict() for c in checks],
        "verdict": verdict.value,
        "verdict_title": verdict.title,
        "reasons": reasons,
        "totals": totals(checks),
        "has_junit": (run_dir / "maestro" / "junit.xml").exists(),
        "duration_sec": round(time.time() - started, 1),
        "notes": [],
    }
    summary["report_path"] = str(run_dir / "report.html")
    summary["history"] = history_rows(runs_dir, apk.package, int(cfg.get_path("report.history_size", 15)))
    # Текущий прогон ещё не сохранён — добавим его в историю для отчёта
    from .history import summary_row
    summary["history"] = (summary["history"] + [summary_row(summary)])[-int(cfg.get_path("report.history_size", 15)):]

    write_junit_all(summary, run_dir / "junit_all.xml")
    report = build_report(summary, run_dir, cfg)
    _save(summary, run_dir)
    append_csv(runs_dir, summary)
    log(f"\n{'=' * 60}\n  ВЕРДИКТ: {verdict.title}\n  Отчёт: {report}\n{'=' * 60}")
    for r in reasons[:8]:
        log(f"  {'✖' if r['level'] == 'block' else '•'} {r['id']} {r['title']}: {r['text'][:110]}")

    run_integrations(summary, report, cfg, opts, log)
    _save(summary, run_dir)
    return summary


def _save(summary: dict, run_dir: Path) -> None:
    data = {k: v for k, v in summary.items() if k != "history"}
    (run_dir / "summary.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def run_integrations(summary: dict, report: Path, cfg: Config, opts: RunOptions, log) -> None:
    use_sheets = cfg.get_path("google_sheets.enabled", False) if opts.sheets is None else opts.sheets
    if use_sheets:
        from .integrations.sheets import export_to_sheets
        try:
            url = export_to_sheets(summary, cfg)
            summary["sheets_url"] = url
            log(f"  Google Таблица: {url}")
        except Exception as e:  # noqa: BLE001 - интеграция не должна ронять прогон
            summary["notes"].append(f"Google Sheets: {e}")
            log(f"  ⚠ Google Sheets: {e}")
    use_tg = cfg.get_path("telegram.enabled", False) if opts.telegram is None else opts.telegram
    if use_tg:
        from .integrations.telegram import send_telegram
        try:
            send_telegram(summary, report, cfg)
            log("  Telegram: отправлено")
        except Exception as e:  # noqa: BLE001
            summary["notes"].append(f"Telegram: {e}")
            log(f"  ⚠ Telegram: {e}")
