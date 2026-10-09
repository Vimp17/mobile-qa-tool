"""Выгрузка результатов в Google Таблицу через сервисный аккаунт.

Два листа:
  «Прогоны»  — одна строка на прогон (вердикт, версия, метрики) → удобно строить графики/фильтры;
  «Проверки» — одна строка на каждую проверку/тест прогона → удобно искать «что падает чаще всего».
Настройка — docs/GOOGLE_SHEETS.md.
"""
from __future__ import annotations

import re
from typing import Any

from ..history import summary_row

RUN_HEADERS = [
    ("run_id", "ID прогона"), ("date", "Дата"), ("project", "Проект"), ("environment", "Окружение"),
    ("package", "Пакет"), ("version_name", "Версия"), ("version_code", "versionCode"), ("build_type", "Тип сборки"),
    ("verdict", "Вердикт"), ("static_fail", "Статика: провалы"), ("static_warn", "Статика: предупреждения"),
    ("device", "Устройство"), ("cold_start_ms", "Холодный старт, мс"), ("memory_mb", "Память, МБ"),
    ("crashes", "Крэши/ANR"), ("tests_total", "Тестов"), ("tests_passed", "Прошло"), ("tests_failed", "Упало"),
    ("tests_flaky", "Нестабильных"), ("apk_size_mb", "Размер APK, МБ"), ("reasons", "Причины"), ("report", "Отчёт"),
]
CHECK_HEADERS = ["ID прогона", "Дата", "Версия", "Раздел", "ID", "Проверка", "Приоритет", "Статус", "Детали"]
CATEGORY_RU = {"static": "Статика", "device": "Устройство", "maestro": "Сценарий"}
STATUS_RU = {"PASS": "OK", "WARN": "Внимание", "FAIL": "Провал", "INFO": "Инфо", "SKIP": "Пропуск",
             "FLAKY": "Нестабилен", "BLOCKED": "Заблокирован"}
VERDICT_COLORS = {"Принять": (0.85, 0.94, 0.87), "Принять с замечаниями": (0.99, 0.93, 0.8),
                  "Не принимать": (0.98, 0.85, 0.84)}


class SheetsError(RuntimeError):
    pass


def _spreadsheet_key(value: str) -> str:
    m = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", value)
    return m.group(1) if m else value.strip()


def run_row(summary: dict[str, Any]) -> list[Any]:
    row = summary_row(summary)
    row["reasons"] = "; ".join(f"{r['id']}: {r['title']}" for r in summary.get("reasons", [])[:8])
    return [row.get(k, "") for k, _ in RUN_HEADERS]


def check_rows(summary: dict[str, Any]) -> list[list[Any]]:
    date = summary.get("timestamp", "")[:19].replace("T", " ")
    ver = f"{summary['apk'].get('version_name')} ({summary['apk'].get('version_code')})"
    rows = []
    for c in summary.get("checks", []):
        details = c.get("details", "")
        if c.get("items"):
            details += " | " + "; ".join(c["items"][:15])
        rows.append([summary["run_id"], date, ver, CATEGORY_RU.get(c["category"], c["category"]), c["id"],
                     c["title"], c.get("priority", ""), STATUS_RU.get(c["status"], c["status"]), details[:1500]])
    return rows


def _get_ws(sh, title: str, headers: list[str]):
    import gspread
    try:
        ws = sh.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=title, rows=1000, cols=len(headers))
        ws.append_row(headers, value_input_option="RAW")
        try:
            ws.format(f"A1:{chr(64 + len(headers))}1", {"textFormat": {"bold": True},
                                                       "backgroundColor": {"red": 0.93, "green": 0.94, "blue": 0.96}})
            ws.freeze(rows=1)
        except Exception:  # noqa: BLE001 - оформление необязательно
            pass
    return ws


def export_to_sheets(summary: dict[str, Any], cfg, client=None) -> str:
    gc_cfg = cfg["google_sheets"]
    if not gc_cfg.get("spreadsheet"):
        raise SheetsError("Не задан google_sheets.spreadsheet (ID или ссылка на таблицу) в qa.yaml")
    if client is None:
        try:
            import gspread
        except ImportError as e:
            raise SheetsError("Не установлен gspread: pip install gspread google-auth") from e
        cred = cfg.resolve(gc_cfg.get("credentials_file", "service_account.json"))
        if not cred.is_file():
            raise SheetsError(f"Нет файла ключа сервисного аккаунта: {cred}")
        client = gspread.service_account(filename=str(cred))
    try:
        sh = client.open_by_key(_spreadsheet_key(gc_cfg["spreadsheet"]))
    except Exception as e:  # noqa: BLE001
        raise SheetsError(f"Нет доступа к таблице: {e}. Поделитесь таблицей с e-mail сервисного аккаунта (роль «Редактор»).") from e

    runs_ws = _get_ws(sh, gc_cfg.get("runs_worksheet", "Прогоны"), [h for _, h in RUN_HEADERS])
    runs_ws.append_row(run_row(summary), value_input_option="USER_ENTERED")
    try:
        color = VERDICT_COLORS.get(summary.get("verdict_title", ""))
        if color:
            n = len(runs_ws.col_values(1))
            col = chr(65 + [k for k, _ in RUN_HEADERS].index("verdict"))
            runs_ws.format(f"{col}{n}", {"backgroundColor": dict(zip(("red", "green", "blue"), color)),
                                         "textFormat": {"bold": True}})
    except Exception:  # noqa: BLE001
        pass

    checks_ws = _get_ws(sh, gc_cfg.get("checks_worksheet", "Проверки"), CHECK_HEADERS)
    rows = check_rows(summary)
    if rows:
        checks_ws.append_rows(rows, value_input_option="RAW")
    return getattr(sh, "url", "") or f"https://docs.google.com/spreadsheets/d/{_spreadsheet_key(gc_cfg['spreadsheet'])}"
