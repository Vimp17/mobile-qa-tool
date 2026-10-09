"""Запуск Maestro-флоу, разбор JUnit, привязка метаданных и доказательств, перезапуск flaky."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import Config
from .models import CheckResult, Status

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".mp4")


@dataclass
class FlowMeta:
    file: Path
    name: str
    test_id: str
    priority: str
    tags: list[str] = field(default_factory=list)


def find_maestro() -> str | None:
    found = shutil.which("maestro")
    if found:
        return found
    cand = Path.home() / ".maestro" / "bin" / "maestro"
    return str(cand) if cand.exists() else None


def load_flows(flows_dir: Path) -> list[FlowMeta]:
    flows: list[FlowMeta] = []
    if not flows_dir.is_dir():
        return flows
    for f in sorted(list(flows_dir.rglob("*.yaml")) + list(flows_dir.rglob("*.yml"))):
        if f.name in ("config.yaml", "config.yml"):
            continue
        try:
            with f.open(encoding="utf-8") as fh:
                header = next(yaml.safe_load_all(fh), None) or {}
        except Exception:  # noqa: BLE001 - битый YAML покажем как упавший тест
            header = {}
        if not isinstance(header, dict):
            header = {}
        props = header.get("properties") or {}
        name = str(header.get("name") or f.stem)
        flows.append(FlowMeta(
            file=f, name=name,
            test_id=str(props.get("testCaseId") or name.split(" ")[0]),
            priority=str(props.get("priority") or "P2"),
            tags=[str(t) for t in header.get("tags") or []],
        ))
    return flows


def filter_flows(flows: list[FlowMeta], include: list[str], exclude: list[str]) -> list[FlowMeta]:
    out = []
    for fl in flows:
        if include and not set(include) & set(fl.tags):
            continue
        if exclude and set(exclude) & set(fl.tags):
            continue
        out.append(fl)
    return out


@dataclass
class JUnitCase:
    name: str
    status: Status
    duration: float
    message: str


def parse_junit(path: Path) -> list[JUnitCase]:
    root = ET.parse(path).getroot()
    out = []
    for i, node in enumerate(root.iter("testcase"), 1):
        name = node.attrib.get("name") or node.attrib.get("id") or f"test-{i}"
        dur = float(node.attrib.get("time") or 0)
        fail = node.find("failure")
        err = node.find("error")
        skip = node.find("skipped")
        if fail is not None or err is not None:
            n = fail if fail is not None else err
            out.append(JUnitCase(name, Status.FAIL, dur, (n.attrib.get("message") or n.text or "").strip()))
        elif skip is not None:
            out.append(JUnitCase(name, Status.BLOCKED, dur, (skip.attrib.get("message") or skip.text or "").strip()))
        else:
            out.append(JUnitCase(name, Status.PASS, dur, ""))
    return out


def _match_flow(case_name: str, flows: list[FlowMeta]) -> FlowMeta | None:
    for fl in flows:
        if case_name in (fl.name, fl.file.stem, fl.file.name):
            return fl
    for fl in flows:
        if fl.test_id and fl.test_id in case_name:
            return fl
    return None


def _evidence_for(flow: FlowMeta | None, case_name: str, out_dir: Path, run_dir: Path) -> list[str]:
    if not out_dir.exists():
        return []
    keys = {case_name}
    if flow:
        keys |= {flow.name, flow.file.stem}
    found = []
    for p in sorted(out_dir.rglob("*")):
        if p.suffix.lower() in IMAGE_EXT and any(k and k in p.name for k in keys):
            found.append(p.relative_to(run_dir).as_posix())
    return found[:6]


def _maestro_cmd(maestro: str, serial: str | None, junit: Path, out_dir: Path, app_id: str,
                 env: dict, targets: list[Path], include: list[str], exclude: list[str]) -> list[str]:
    cmd = [maestro]
    if serial:
        cmd += ["--device", serial]
    cmd += ["test", "--format", "junit", "--output", str(junit), "--test-output-dir", str(out_dir),
            "-e", f"MAESTRO_APP_ID={app_id}", "-e", f"APP_ID={app_id}"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    if include:
        cmd += ["--include-tags", ",".join(include)]
    if exclude:
        cmd += ["--exclude-tags", ",".join(exclude)]
    cmd += [str(t) for t in targets]
    return cmd


def run_maestro(cfg: Config, run_dir: Path, app_id: str, serial: str | None, log=print,
                maestro_bin: str | None = None) -> list[CheckResult]:
    mc = cfg["maestro"]
    flows_dir = cfg.resolve(cfg.get_path("paths.flows_dir", ".maestro/smoke"))
    maestro = maestro_bin or find_maestro()
    if not maestro:
        return [CheckResult("MA00", "Сценарии Maestro", Status.SKIP,
                            "Maestro не установлен — выполнена только базовая проверка. Установка: https://docs.maestro.dev/",
                            category="maestro")]
    flows = filter_flows(load_flows(flows_dir), mc.get("include_tags") or [], mc.get("exclude_tags") or [])
    if not flows:
        return [CheckResult("MA00", "Сценарии Maestro", Status.SKIP, f"Нет флоу в {flows_dir}", category="maestro")]

    out_root = run_dir / "maestro"
    out_root.mkdir(parents=True, exist_ok=True)
    junit = out_root / "junit.xml"
    log(f"  Maestro: {len(flows)} флоу…")
    cmd = _maestro_cmd(maestro, serial, junit, out_root / "output", app_id, mc.get("env") or {},
                       [flows_dir], mc.get("include_tags") or [], mc.get("exclude_tags") or [])
    (out_root / "command.txt").write_text(" ".join(cmd), encoding="utf-8")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=int(mc.get("timeout_sec", 1800)))
        (out_root / "maestro_stdout.txt").write_bytes(proc.stdout + b"\n" + proc.stderr)
    except subprocess.TimeoutExpired:
        return [CheckResult("MA00", "Сценарии Maestro", Status.BLOCKED,
                            f"Таймаут {mc.get('timeout_sec')} с", category="maestro")]
    if not junit.exists():
        tail = (proc.stdout + proc.stderr).decode(errors="replace").strip().splitlines()[-8:]
        return [CheckResult("MA00", "Сценарии Maestro", Status.BLOCKED,
                            "Maestro не сформировал JUnit-отчёт. " + " | ".join(tail),
                            category="maestro", evidence=["maestro/maestro_stdout.txt"])]

    cases = parse_junit(junit)
    results = [_to_result(c, flows, out_root / "output", run_dir) for c in cases]

    # --- перезапуск упавших: отделяем нестабильные тесты от настоящих багов -------------
    retries = int(mc.get("retries", 0) or 0)
    for attempt in range(1, retries + 1):
        failed = [r for r in results if r.status == Status.FAIL and r.extra.get("flow_file")]
        if not failed:
            break
        log(f"  Maestro: перезапуск {len(failed)} упавших (попытка {attempt})…")
        for r in failed:
            rj = out_root / f"retry{attempt}_{Path(r.extra['flow_file']).stem}.xml"
            rcmd = _maestro_cmd(maestro, serial, rj, out_root / f"retry{attempt}", app_id, mc.get("env") or {},
                                [Path(r.extra["flow_file"])], [], [])
            try:
                subprocess.run(rcmd, capture_output=True, timeout=int(mc.get("timeout_sec", 1800)))
            except subprocess.TimeoutExpired:
                continue
            if rj.exists():
                rc = parse_junit(rj)
                if rc and all(c.status == Status.PASS for c in rc):
                    r.status = Status.FLAKY
                    r.details = f"Упал, но прошёл при перезапуске №{attempt}. Первая ошибка: {r.details}"
    return results


def _to_result(c: JUnitCase, flows: list[FlowMeta], out_dir: Path, run_dir: Path) -> CheckResult:
    fl = _match_flow(c.name, flows)
    return CheckResult(
        id=fl.test_id if fl else c.name,
        title=fl.name if fl else c.name,
        status=c.status,
        details=c.message,
        category="maestro",
        priority=fl.priority if fl else "",
        duration_sec=round(c.duration, 2),
        evidence=_evidence_for(fl, c.name, out_dir, run_dir),
        extra={"flow_file": str(fl.file) if fl else "", "tags": fl.tags if fl else []},
    )
