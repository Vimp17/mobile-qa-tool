"""Загрузка конфигурации qa.yaml с умолчаниями и подстановкой ${ENV}."""
from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

import yaml

try:  # .env необязателен
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


DEFAULTS: dict[str, Any] = {
    "project": {
        "name": "Mobile App",
        "environment": "TEST",
        # Ожидаемый applicationId. Если задан, а в APK другой — сборку не принимаем
        # (типичная ошибка: прислали dev-флейвор вместо prod).
        "expected_app_id": "",
        # release | debug. Для release строже: debuggable, отладочная подпись, cleartext = FAIL.
        "build_type": "release",
    },
    "paths": {
        "runs_dir": "qa_runs",
        "flows_dir": ".maestro/smoke",
    },
    "static": {
        "min_target_sdk": 36,            # требование Google Play с 31.08.2026
        "min_sdk_floor": 0,              # если >0 — предупреждать, когда minSdk ниже
        "max_apk_size_mb": 150,
        "size_growth_warn_pct": 10,
        "cert_expiry_warn_days": 30,
        "expected_locales": [],          # например ["ru", "en"]
        # Подстроки URL, которых не должно быть в release-сборке (стенды, моки).
        "forbidden_url_patterns": ["staging", "stage.", "dev.", "test.", "localhost", "10.0.2.2", "ngrok"],
        "ignore_hosts": [
            "schemas.android.com", "www.w3.org", "w3.org", "xmlpull.org", "www.apache.org",
            "apache.org", "ns.adobe.com", "purl.org", "xml.org", "www.xml.org", "json-schema.org",
            "developer.android.com", "www.google.com", "goo.gl", "github.com", "www.example.com",
            "example.com", "schemas.microsoft.com", "www.slf4j.org", "javax.xml.XMLConstants",
            "xml.apache.org", "java.sun.com", "ns.android.com", "issuetracker.google.com",
            "plus.google.com", "www.googleapis.com", "openjdk.org", "bugs.openjdk.org",
        ],
        # Переопределение статуса проверок: {"S06": "INFO", "S13": "SKIP"}
        "severity_overrides": {},
    },
    "device": {
        "enabled": True,
        "serial": "",                    # пусто = первое доступное устройство (эмулятор в приоритете)
        "boot_timeout_sec": 120,
        "clean_install": True,           # удалить приложение перед установкой (чистое состояние)
        "grant_permissions": True,       # adb install -g
        "launch_runs": 3,                # сколько раз мерить холодный старт
        "settle_sec": 5,                 # сколько ждать после старта перед проверкой «жив ли процесс»
        "cold_start_warn_ms": 2000,
        "cold_start_fail_ms": 5000,
        "monkey_events": 500,            # 0 — не запускать monkey
        "monkey_throttle_ms": 100,
        "monkey_seed": 42,
    },
    "maestro": {
        "enabled": True,
        "include_tags": [],              # например ["smoke"]
        "exclude_tags": [],
        "retries": 1,                    # перезапуск упавших флоу для выявления flaky
        "timeout_sec": 1800,
        "env": {},                       # доп. переменные -e KEY=VALUE для флоу
    },
    "verdict": {
        # Падение тестов этих приоритетов = «Не принимать»
        "blocker_priorities": ["P0"],
        # Без проверки на устройстве вердикт не может быть лучше «с замечаниями»
        "require_device": True,
    },
    "report": {
        "embed_images": True,            # вшивать скриншоты в HTML (один файл можно переслать)
        "image_width": 360,
        "history_size": 15,
        "open_after_run": False,
    },
    "google_sheets": {
        "enabled": False,
        "credentials_file": "service_account.json",
        "spreadsheet": "",               # ID или полная ссылка на таблицу
        "runs_worksheet": "Прогоны",
        "checks_worksheet": "Проверки",
    },
    "telegram": {
        "enabled": False,
        "bot_token": "${TELEGRAM_BOT_TOKEN}",
        "chat_id": "${TELEGRAM_CHAT_ID}",
        "send_report_file": True,
    },
}

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.getenv(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config(dict):
    """dict с доступом через точку: cfg.get_path('device.serial')."""

    base_dir: Path = Path.cwd()

    def get_path(self, dotted: str, default: Any = None) -> Any:
        node: Any = self
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def resolve(self, rel: str | os.PathLike) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else (self.base_dir / p)


def find_config(start: Path | None = None) -> Path | None:
    start = (start or Path.cwd()).resolve()
    for d in [start, *start.parents]:
        for name in ("qa.yaml", "qa.yml"):
            if (d / name).is_file():
                return d / name
    return None


def load_config(path: str | os.PathLike | None = None, overrides: dict | None = None) -> Config:
    cfg_path = Path(path) if path else find_config()
    user: dict = {}
    base_dir = Path.cwd()
    if cfg_path:
        cfg_path = cfg_path.resolve()
        base_dir = cfg_path.parent
        if load_dotenv:
            load_dotenv(base_dir / ".env")
        with cfg_path.open(encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
    elif load_dotenv:
        load_dotenv()
    merged = deep_merge(DEFAULTS, user)
    if overrides:
        merged = deep_merge(merged, overrides)
    cfg = Config(_expand_env(merged))
    cfg.base_dir = base_dir
    cfg["_config_file"] = str(cfg_path) if cfg_path else ""
    return cfg
