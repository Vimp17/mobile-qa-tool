"""Командная строка: qa check / static / doctor / history / report / init / demo."""
from __future__ import annotations

import argparse
import importlib
import json
import re
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .config import load_config

TEMPLATES = Path(__file__).parent / "templates"


def _utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass


def _exit_code(summary: dict, fail_on: str) -> int:
    v = summary["verdict"]
    if fail_on == "never":
        return 0
    if fail_on == "remarks" and v != "GO":
        return 2 if v == "NO_GO" else 1
    return 2 if v == "NO_GO" else 0


def cmd_check(args, static_only: bool = False) -> int:
    from .pipeline import RunOptions, run_check

    overrides: dict = {}
    if args.build_type:
        overrides.setdefault("project", {})["build_type"] = args.build_type
    if getattr(args, "flows", None):
        overrides.setdefault("paths", {})["flows_dir"] = args.flows
    if getattr(args, "monkey_events", None) is not None:
        overrides.setdefault("device", {})["monkey_events"] = args.monkey_events
    cfg = load_config(args.config, overrides)
    opts = RunOptions(
        device=getattr(args, "device", None),
        skip_device=static_only or getattr(args, "skip_device", False),
        skip_maestro=getattr(args, "skip_maestro", False),
        no_monkey=getattr(args, "no_monkey", False),
        expect_version=args.expect_version,
        sheets=True if args.sheets else (False if args.no_sheets else None),
        telegram=True if args.telegram else None,
    )
    try:
        summary = run_check(args.apk, cfg, opts)
    except (FileNotFoundError, ValueError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 3
    if args.open or cfg.get_path("report.open_after_run"):
        webbrowser.open(Path(summary["report_path"]).resolve().as_uri())
    return _exit_code(summary, args.fail_on)


def _ok(flag: bool | None, text: str, hint: str = "") -> None:
    mark = {True: "✓", False: "✗", None: "!"}[flag]
    print(f"  {mark} {text}" + (f"\n      → {hint}" if hint else ""))


def _version(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)
        out = [ln for ln in (r.stdout + r.stderr).decode(errors="replace").strip().splitlines()
               if ln.strip() and not ln.startswith("Picked up")]
        return out[0] if out else ""
    except Exception:  # noqa: BLE001
        return ""


def cmd_doctor(args) -> int:
    from .device.adb import Adb, AdbError, find_adb
    from .maestro import find_maestro, load_flows

    cfg = load_config(args.config)
    problems = 0
    print(f"qa-tool {__version__} — проверка окружения\n")
    print("Python и библиотеки")
    _ok(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]}", "" if sys.version_info >= (3, 10) else "нужен Python 3.10+")
    for mod, need, hint in (("yaml", True, "pip install -r requirements.txt"), ("jinja2", True, "pip install -r requirements.txt"),
                            ("cryptography", False, "без него не будет данных о сертификате"),
                            ("PIL", False, "без Pillow скриншоты не сжимаются (отчёт тяжелее)"),
                            ("requests", False, "нужен для Telegram"),
                            ("gspread", False, "нужен для Google Таблиц: pip install gspread google-auth")):
        try:
            importlib.import_module(mod)
            _ok(True, mod)
        except ImportError:
            _ok(False if need else None, f"{mod} не установлен", hint)
            problems += need

    print("\nКонфигурация")
    if cfg["_config_file"]:
        _ok(True, f"qa.yaml: {cfg['_config_file']}")
    else:
        _ok(None, "qa.yaml не найден — используются значения по умолчанию", "создайте: qa init")
    _ok(None if not cfg.get_path("project.expected_app_id") else True,
        f"ожидаемый пакет: {cfg.get_path('project.expected_app_id') or 'не задан'}",
        "" if cfg.get_path("project.expected_app_id") else "задайте project.expected_app_id — поймаем «не ту» сборку")

    print("\nAndroid")
    adb_path = find_adb()
    if not adb_path:
        _ok(False, "adb не найден", "установите Android Studio или platform-tools и добавьте в PATH")
        problems += 1
    else:
        _ok(True, f"adb: {adb_path} ({_version([adb_path, 'version'])})")
        try:
            adb = Adb(adb_path=adb_path)
            devs = adb.devices()
            if not devs:
                _ok(False, "нет запущенных эмуляторов/устройств", "запустите эмулятор: Android Studio → Device Manager")
                problems += 1
            for d in devs:
                _ok(d.state == "device", f"{d.serial} [{d.state}] {d.model}",
                    "" if d.state == "device" else "разрешите отладку по USB на устройстве")
        except AdbError as e:
            _ok(False, str(e))
            problems += 1

    print("\nMaestro (сценарии)")
    java = shutil.which("java")
    jv = _version(["java", "-version"]) if java else ""
    jm = re.search(r'version "(\d+)', jv)
    java_ok = bool(jm and int(jm.group(1)) >= 17)
    _ok(java_ok or None, f"java: {jv or 'не найдена'}", "" if java_ok else "Maestro требует Java 17+")
    m = find_maestro()
    _ok(bool(m) or None, f"maestro: {m or 'не установлен'}",
        "" if m else "без Maestro работает только базовая проверка. https://docs.maestro.dev/getting-started/installing-maestro")
    flows = load_flows(cfg.resolve(cfg.get_path("paths.flows_dir")))
    _ok(bool(flows) or None, f"флоу в {cfg.get_path('paths.flows_dir')}: {len(flows)}")

    print("\nИнтеграции")
    gs = cfg["google_sheets"]
    if gs.get("enabled"):
        cred = cfg.resolve(gs.get("credentials_file", ""))
        _ok(cred.is_file(), f"ключ сервисного аккаунта: {cred}", "" if cred.is_file() else "см. docs/GOOGLE_SHEETS.md")
        _ok(bool(gs.get("spreadsheet")), f"таблица: {gs.get('spreadsheet') or 'не задана'}")
        if cred.is_file():
            try:
                email = json.loads(cred.read_text(encoding="utf-8")).get("client_email", "")
                print(f"      поделитесь таблицей с: {email}")
            except Exception:  # noqa: BLE001
                pass
        if args.online and cred.is_file() and gs.get("spreadsheet"):
            try:
                import gspread

                from .integrations.sheets import _spreadsheet_key
                sh = gspread.service_account(filename=str(cred)).open_by_key(_spreadsheet_key(gs["spreadsheet"]))
                _ok(True, f"доступ к таблице «{sh.title}» есть")
            except Exception as e:  # noqa: BLE001
                _ok(False, f"нет доступа к таблице: {e}")
                problems += 1
    else:
        _ok(None, "Google Таблицы выключены (google_sheets.enabled: false)")
    tg = cfg["telegram"]
    _ok(None if not tg.get("enabled") else bool(tg.get("bot_token") and tg.get("chat_id")),
        "Telegram " + ("включён" if tg.get("enabled") else "выключен"))

    print("\nИтог: " + ("всё готово ✓" if not problems else f"проблем: {problems}"))
    return 0 if not problems else 1


def cmd_history(args) -> int:
    from .history import load_runs, summary_row

    cfg = load_config(args.config)
    runs = load_runs(cfg.resolve(cfg.get_path("paths.runs_dir")))
    rows = [summary_row(r) for r in runs if not args.package or (r.get("apk") or {}).get("package") == args.package]
    if not rows:
        print("Прогонов пока нет.")
        return 0
    print(f"{'Дата':19}  {'Пакет':28} {'Версия':14} {'Вердикт':22} {'F/W':7} {'Тесты':7} {'Старт':8}")
    for r in rows[-args.limit:]:
        tests = f"{r['tests_passed']}/{r['tests_total']}" if r["tests_total"] else "—"
        cs = f"{r['cold_start_ms']}мс" if r["cold_start_ms"] != "" else "—"
        print(f"{r['date']:19}  {r['package'][:28]:28} {str(r['version_name'])[:14]:14} {r['verdict']:22} "
              f"{r['static_fail']}/{r['static_warn']:<5} {tests:7} {cs:8}")
    return 0


def cmd_report(args) -> int:
    from .history import history_rows
    from .report.html import build_report

    cfg = load_config(args.config)
    run_dir = Path(args.run_dir)
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    summary["history"] = [h for h in history_rows(run_dir.parent, summary["apk"]["package"], 100)
                          if h["date"] <= summary["timestamp"][:19].replace("T", " ")][-int(cfg.get_path("report.history_size", 15)):]
    path = build_report(summary, run_dir, cfg)
    print(f"Отчёт: {path}")
    if args.open:
        webbrowser.open(path.resolve().as_uri())
    return 0


def cmd_init(args) -> int:
    target = Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    created = []
    for src in TEMPLATES.rglob("*"):
        if src.is_dir():
            continue
        rel = src.relative_to(TEMPLATES)
        rel = Path(str(rel).replace("dot_maestro", ".maestro").replace("dot_env.example", ".env.example"))
        dst = target / rel
        if dst.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        created.append(str(rel))
    print("Созданы файлы:\n  " + "\n  ".join(created) if created else "Все файлы уже есть, ничего не перезаписано.")
    print("\nДальше: отредактируйте qa.yaml (project.expected_app_id) и выполните `qa doctor`.")
    return 0


def cmd_demo(args) -> int:
    from .demo import run_demo

    summary = run_demo(Path(args.out))
    if args.open:
        webbrowser.open(Path(summary["report_path"]).resolve().as_uri())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="qa", description="Автоматическая базовая проверка Android-сборок.")
    p.add_argument("--version", action="version", version=f"qa-tool {__version__}")
    p.add_argument("-c", "--config", help="путь к qa.yaml (по умолчанию ищется в текущей папке и выше)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("apk", help="путь к .apk")
        sp.add_argument("--build-type", choices=["release", "debug"], help="переопределить project.build_type")
        sp.add_argument("--expect-version", help="ожидаемая версия (versionName или versionCode)")
        sp.add_argument("--sheets", action="store_true", help="выгрузить в Google Таблицу")
        sp.add_argument("--no-sheets", action="store_true", help="не выгружать в Google Таблицу")
        sp.add_argument("--telegram", action="store_true", help="отправить итог в Telegram")
        sp.add_argument("--open", action="store_true", help="открыть отчёт в браузере")
        sp.add_argument("--fail-on", choices=["nogo", "remarks", "never"], default="nogo",
                        help="код выхода ≠0 при: nogo (по умолчанию), remarks, never")

    c = sub.add_parser("check", help="полная проверка: статика + эмулятор + сценарии + отчёт")
    common(c)
    c.add_argument("-d", "--device", help="serial устройства (adb devices)")
    c.add_argument("--skip-device", action="store_true", help="только статический анализ")
    c.add_argument("--skip-maestro", action="store_true", help="не запускать Maestro-флоу")
    c.add_argument("--no-monkey", action="store_true", help="не запускать monkey-стресс")
    c.add_argument("--monkey-events", type=int, help="число событий monkey")
    c.add_argument("--flows", help="папка с флоу (по умолчанию paths.flows_dir)")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("static", help="только статический анализ APK (без устройства)")
    common(s)
    s.set_defaults(func=lambda a: cmd_check(a, static_only=True))

    d = sub.add_parser("doctor", help="проверить окружение: adb, эмулятор, Maestro, интеграции")
    d.add_argument("--online", action="store_true", help="проверить доступ к Google Таблице")
    d.set_defaults(func=cmd_doctor)

    h = sub.add_parser("history", help="история прогонов")
    h.add_argument("--package")
    h.add_argument("--limit", type=int, default=30)
    h.set_defaults(func=cmd_history)

    r = sub.add_parser("report", help="пересобрать HTML-отчёт для папки прогона")
    r.add_argument("run_dir")
    r.add_argument("--open", action="store_true")
    r.set_defaults(func=cmd_report)

    i = sub.add_parser("init", help="создать qa.yaml и примеры флоу в папке")
    i.add_argument("dir", nargs="?", default=".")
    i.set_defaults(func=cmd_init)

    dm = sub.add_parser("demo", help="демо-отчёт без эмулятора (синтетические APK)")
    dm.add_argument("--out", default="qa_demo")
    dm.add_argument("--open", action="store_true")
    dm.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    _utf8_console()
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
