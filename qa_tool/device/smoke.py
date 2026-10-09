"""Базовая проверка на эмуляторе/устройстве — работает даже без написанных тестов.

Установка → холодный старт (замер) → «жив ли процесс» → скриншот → память →
[Maestro-флоу] → monkey-стресс → анализ logcat на крэши и ANR.
"""
from __future__ import annotations

import re
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..apk.apk import ApkInfo
from ..config import Config
from ..models import CheckResult, Status
from .adb import Adb, AdbError, DeviceInfo
from .logcat import STAGE_TAG, Crash, parse_crashes, parse_monkey

Log = Callable[[str], None]


@dataclass
class DeviceStage:
    device: DeviceInfo | None = None
    checks: list[CheckResult] = field(default_factory=list)
    crashes: list[Crash] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    logcat_file: str = ""
    blocked_reason: str = ""


def _dv(id_, title, status, details="", **kw) -> CheckResult:
    return CheckResult(id=id_, title=title, status=status, details=details, category="device", **kw)


def _mark(adb: Adb, stage: str) -> None:
    adb.shell(f"log -t {STAGE_TAG} 'STAGE: {stage}'")


TOTAL_TIME_RE = re.compile(r"TotalTime:\s*(\d+)")
PSS_RE = re.compile(r"TOTAL PSS:\s+(\d+)|^\s*TOTAL\s+(\d+)", re.M)


def run_device_stage(apk: ApkInfo, cfg: Config, run_dir: Path, serial: str | None = None,
                     between: Callable[[Adb, DeviceInfo], list[CheckResult]] | None = None,
                     monkey: bool = True, log: Log = print, adb: Adb | None = None) -> DeviceStage:
    dc = cfg["device"]
    stage = DeviceStage()
    pkg = apk.package
    dev_dir = run_dir / "device"
    dev_dir.mkdir(parents=True, exist_ok=True)

    # --- устройство -------------------------------------------------------
    try:
        adb = adb or Adb()
        dev = adb.select(serial or dc.get("serial") or None)
    except AdbError as e:
        stage.blocked_reason = str(e)
        stage.checks.append(_dv("DV00", "Устройство", Status.BLOCKED, str(e)))
        return stage
    stage.device = dev
    log(f"  устройство: {dev.title} [{dev.serial}]")
    if not adb.wait_boot(int(dc.get("boot_timeout_sec", 120))):
        stage.blocked_reason = "эмулятор не догрузился"
        stage.checks.append(_dv("DV00", "Устройство", Status.BLOCKED, "Устройство не завершило загрузку (sys.boot_completed≠1)."))
        return stage

    if dev.sdk and apk.min_sdk and apk.min_sdk > dev.sdk:
        stage.blocked_reason = "версия Android ниже minSdk"
        stage.checks.append(_dv("DV00", "Совместимость устройства", Status.BLOCKED,
                                f"На устройстве API {dev.sdk}, приложению нужен minSdk {apk.min_sdk}. Возьмите эмулятор новее."))
        return stage
    if apk.native.has_native and dev.abis and not set(apk.native.abis) & set(dev.abis):
        stage.blocked_reason = "нет подходящего ABI"
        stage.checks.append(_dv("DV00", "Совместимость устройства", Status.BLOCKED,
                                f"В APK библиотеки {', '.join(apk.native.abis)}, устройство поддерживает {', '.join(dev.abis)}."))
        return stage
    stage.checks.append(_dv("DV00", "Устройство", Status.PASS, f"{dev.title}, экран {dev.screen or '?'}"))

    logcat_path = dev_dir / "logcat.txt"
    stage.logcat_file = logcat_path.relative_to(run_dir).as_posix()
    try:
        adb.logcat_clear()
    except AdbError:
        pass
    lc = adb.logcat_start(logcat_path)
    try:
        _run_steps(adb, dev, apk, cfg, run_dir, dev_dir, stage, between, monkey, log)
    finally:
        time.sleep(1)
        Adb.logcat_stop(lc)

    # --- крэши и ANR ------------------------------------------------------
    text = logcat_path.read_text(encoding="utf-8", errors="replace") if logcat_path.exists() else ""
    stage.crashes = parse_crashes(text, pkg)
    if stage.crashes:
        items = [f"[{c.stage}] {c.kind_title}: {c.title}" for c in stage.crashes]
        stage.checks.append(_dv("DV09", "Крэши и ANR в logcat", Status.FAIL,
                                f"Найдено: {len(stage.crashes)}. Полные стектрейсы — в разделе «Крэши».",
                                items=items, evidence=[stage.logcat_file]))
    else:
        stage.checks.append(_dv("DV09", "Крэши и ANR в logcat", Status.PASS,
                                "Падений приложения не найдено.", evidence=[stage.logcat_file]))
    return stage


def _run_steps(adb: Adb, dev: DeviceInfo, apk: ApkInfo, cfg: Config, run_dir: Path, dev_dir: Path,
               stage: DeviceStage, between, monkey: bool, log: Log) -> None:
    dc = cfg["device"]
    pkg = apk.package
    rel = lambda p: Path(p).relative_to(run_dir).as_posix()  # noqa: E731

    # --- установка --------------------------------------------------------
    _mark(adb, "install")
    log("  установка…")
    if dc.get("clean_install", True) and adb.is_installed(pkg):
        adb.uninstall(pkg)
    t0 = time.time()
    ok, out = adb.install(apk.path, grant=bool(dc.get("grant_permissions", True)), test_only=apk.test_only)
    install_sec = round(time.time() - t0, 1)
    stage.metrics["install_sec"] = install_sec
    if not ok:
        reason = re.search(r"(INSTALL_[A-Z_]+[^\]\n]*)", out)
        stage.checks.append(_dv("DV01", "Установка", Status.FAIL,
                                f"Не установилось: {reason.group(1) if reason else out[-400:]}", duration_sec=install_sec))
        stage.blocked_reason = "установка не удалась"
        return
    stage.checks.append(_dv("DV01", "Установка", Status.PASS,
                            ("Чистая установка" if dc.get("clean_install", True) else "Установка поверх")
                            + f" за {install_sec} с" + (", разрешения выданы (-g)" if dc.get("grant_permissions", True) else ""),
                            duration_sec=install_sec))

    # --- холодный старт ---------------------------------------------------
    _mark(adb, "launch")
    log("  холодный старт…")
    runs = max(1, int(dc.get("launch_runs", 3)))
    times: list[int] = []
    launch_error = ""
    for _ in range(runs):
        adb.force_stop(pkg)
        time.sleep(1)
        if apk.launcher_activity:
            out = adb.shell(f"am start -W -n {pkg}/{apk.launcher_activity}", timeout=60)
        else:
            out = adb.shell(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1", timeout=60)
        m = TOTAL_TIME_RE.search(out)
        if m:
            times.append(int(m.group(1)))
        if "Error" in out or "Exception" in out:
            launch_error = out.strip().splitlines()[-1][:300]
            break
    if launch_error:
        stage.checks.append(_dv("DV02", "Запуск приложения", Status.FAIL, launch_error))
    elif times:
        med = int(statistics.median(times))
        stage.metrics["cold_start_ms"] = med
        stage.metrics["cold_start_runs"] = times
        warn, fail = int(dc.get("cold_start_warn_ms", 2000)), int(dc.get("cold_start_fail_ms", 5000))
        st = Status.FAIL if med >= fail else Status.WARN if med >= warn else Status.PASS
        stage.checks.append(_dv("DV02", "Холодный старт", st,
                                f"Медиана {med} мс по {len(times)} запускам ({', '.join(map(str, times))}). "
                                f"Порог: предупреждение {warn} мс, провал {fail} мс.",
                                extra={"times": times}))
    else:
        stage.checks.append(_dv("DV02", "Холодный старт", Status.INFO,
                                "Приложение запущено через launcher, время не измерено (нет launcher activity в манифесте)."))

    # --- приложение живо и на экране -------------------------------------
    time.sleep(float(dc.get("settle_sec", 5)))
    pid = adb.pidof(pkg)
    focus = adb.shell("dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity|ResumedActivity'")
    shot = dev_dir / "screens" / "01_after_launch.png"
    has_shot = adb.screenshot(shot)
    ev = [rel(shot)] if has_shot else []
    if not pid:
        stage.checks.append(_dv("DV03", "Приложение работает после старта", Status.FAIL,
                                f"Через {dc.get('settle_sec', 5)} с процесс {pkg} не найден — вероятно, упало.", evidence=ev))
    elif pkg not in focus:
        stage.checks.append(_dv("DV03", "Приложение работает после старта", Status.WARN,
                                "Процесс жив, но приложение не на переднем плане (системный диалог? переход в браузер?).",
                                evidence=ev, extra={"focus": focus[:300]}))
    else:
        stage.checks.append(_dv("DV03", "Приложение работает после старта", Status.PASS,
                                f"Процесс жив (pid {pid.split()[0]}), экран приложения на переднем плане.", evidence=ev))

    # --- память -------------------------------------------------------------
    if pid:
        mem = adb.shell(f"dumpsys meminfo {pkg}", timeout=60)
        m = PSS_RE.search(mem)
        if m:
            kb = int(m.group(1) or m.group(2))
            stage.metrics["memory_pss_mb"] = round(kb / 1024, 1)
            stage.checks.append(_dv("DV04", "Память после старта (PSS)", Status.INFO, f"{round(kb / 1024, 1)} МБ"))

    # --- сценарии Maestro --------------------------------------------------
    if between:
        _mark(adb, "maestro")
        stage.checks.extend(between(adb, dev))

    # --- monkey ---------------------------------------------------------------
    events = int(dc.get("monkey_events", 0) or 0)
    if monkey and events > 0:
        _mark(adb, "monkey")
        log(f"  monkey: {events} событий…")
        adb.force_stop(pkg)
        throttle = int(dc.get("monkey_throttle_ms", 100))
        cmd = (f"monkey -p {pkg} -s {int(dc.get('monkey_seed', 42))} --throttle {throttle} "
               f"--pct-syskeys 0 --pct-appswitch 5 -v {events}")
        t0 = time.time()
        out = adb.shell(cmd, timeout=int(events * throttle / 1000) + 180)
        dur = round(time.time() - t0, 1)
        (dev_dir / "monkey.txt").write_text(out, encoding="utf-8")
        res = parse_monkey(out, pkg)
        shot = dev_dir / "screens" / "02_after_monkey.png"
        ev = [rel(dev_dir / "monkey.txt")] + ([rel(shot)] if adb.screenshot(shot) else [])
        if res["crash"] or res["anr"]:
            what = "крэш" if res["crash"] else "ANR"
            stage.checks.append(_dv("DV05", "Monkey-стресс", Status.FAIL,
                                    f"{what} после {res['injected'] or '?'} из {events} случайных действий (seed "
                                    f"{dc.get('monkey_seed', 42)} — можно воспроизвести).", duration_sec=dur, evidence=ev))
        elif res["aborted"] and not res["finished"]:
            stage.checks.append(_dv("DV05", "Monkey-стресс", Status.WARN, "Monkey прерван (см. monkey.txt).",
                                    duration_sec=dur, evidence=ev))
        else:
            stage.checks.append(_dv("DV05", "Monkey-стресс", Status.PASS,
                                    f"{res['injected'] or events} случайных действий без падений.", duration_sec=dur, evidence=ev))
    adb.force_stop(pkg)
