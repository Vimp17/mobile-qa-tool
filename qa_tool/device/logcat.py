"""Поиск крэшей, ANR и нативных падений приложения в logcat (формат -v threadtime)."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

LINE_RE = re.compile(r"^(\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEFA])\s+(.*?)\s*:\s?(.*)$")
STAGE_TAG = "QA_TOOL"


@dataclass
class Crash:
    kind: str        # java | anr | native
    title: str
    time: str
    stage: str
    text: str

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def kind_title(self) -> str:
        return {"java": "Крэш (Java/Kotlin)", "anr": "ANR (не отвечает)", "native": "Нативный крэш"}[self.kind]


def parse_crashes(text: str, package: str, max_lines: int = 60) -> list[Crash]:
    lines = text.splitlines()
    parsed = [LINE_RE.match(line) for line in lines]
    crashes: list[Crash] = []
    stage = "—"
    seen_native_pids: set[str] = set()
    i = 0
    while i < len(lines):
        m = parsed[i]
        if not m:
            i += 1
            continue
        ts, pid, _tid, _lvl, tag, msg = m.groups()
        if tag == STAGE_TAG and msg.startswith("STAGE:"):
            stage = msg.split(":", 1)[1].strip()
        elif tag == "AndroidRuntime" and msg.startswith("FATAL EXCEPTION"):
            block = _collect(lines, parsed, i, lambda g: g[4] == "AndroidRuntime" and g[1] == pid, max_lines)
            body = [b[5] for b in block]
            if any(f"Process: {package}," in b or b.strip() == f"Process: {package}" for b in body):
                title = next((b for b in body[1:] if b and not b.startswith("Process:")), msg)
                crashes.append(Crash("java", title.strip(), ts, stage, "\n".join(body)))
        elif tag == "ActivityManager" and msg.startswith(f"ANR in {package}"):
            block = _collect(lines, parsed, i, lambda g: g[4] == "ActivityManager", 20)
            body = [b[5] for b in block]
            reason = next((b for b in body if b.startswith("Reason:")), msg)
            crashes.append(Crash("anr", reason.strip(), ts, stage, "\n".join(body)))
        elif tag == "libc" and "Fatal signal" in msg and f"({package})" in msg:
            npid = re.search(r"pid (\d+)", msg)
            key = npid.group(1) if npid else ts
            if key not in seen_native_pids:
                seen_native_pids.add(key)
                block = _collect(lines, parsed, i, lambda g: g[4] in ("DEBUG", "libc", "crash_dump64", "crash_dump32", "tombstoned"), max_lines, gap=200)
                crashes.append(Crash("native", msg.strip(), ts, stage, "\n".join(b[5] for b in block)))
        i += 1
    return crashes


def _collect(lines, parsed, start, pred, limit, gap=50):
    """Собирает строки, удовлетворяющие pred, начиная с start; допускает вкрапления чужих строк."""
    out = []
    misses = 0
    j = start
    while j < len(lines) and len(out) < limit and misses < gap:
        m = parsed[j]
        if m and pred(m.groups()):
            out.append(m.groups())
            misses = 0
        else:
            misses += 1
        j += 1
    return out


MONKEY_CRASH_RE = re.compile(r"// CRASH: (\S+)")
MONKEY_ANR_RE = re.compile(r"// NOT RESPONDING: (\S+)")
MONKEY_INJECTED_RE = re.compile(r"Events injected: (\d+)")


def parse_monkey(output: str, package: str) -> dict:
    crash = any(m.group(1) == package for m in MONKEY_CRASH_RE.finditer(output))
    anr = any(m.group(1) == package for m in MONKEY_ANR_RE.finditer(output))
    inj = MONKEY_INJECTED_RE.search(output)
    return {
        "crash": crash,
        "anr": anr,
        "aborted": "Monkey aborted" in output,
        "injected": int(inj.group(1)) if inj else None,
        "finished": "// Monkey finished" in output,
    }
