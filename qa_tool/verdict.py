"""Итоговый вердикт по сборке и причины."""
from __future__ import annotations

from .config import Config
from .models import CheckResult, Status, Verdict


def compute_verdict(checks: list[CheckResult], cfg: Config, device_ran: bool) -> tuple[Verdict, list[dict]]:
    blockers = [p.upper() for p in cfg.get_path("verdict.blocker_priorities", ["P0"])]
    reasons: list[dict] = []

    def add(level: str, c: CheckResult, text: str | None = None):
        reasons.append({"level": level, "id": c.id, "title": c.title, "text": text or c.details,
                        "category": c.category})

    for c in checks:
        if c.category == "maestro":
            if c.status == Status.FAIL:
                if (c.priority or "").upper() in blockers:
                    add("block", c, f"Упал тест {c.priority}: {c.details}")
                else:
                    add("remark", c, f"Упал тест {c.priority or ''}: {c.details}".strip())
            elif c.status == Status.BLOCKED:
                add("remark", c)
            elif c.status == Status.FLAKY:
                add("remark", c, "Нестабильный тест: " + c.details)
            elif c.status == Status.WARN:
                add("remark", c)
        elif c.category == "device" and c.id == "DV00" and c.status == Status.BLOCKED:
            add("remark", c, "Проверка на устройстве не выполнена: " + c.details)
        else:
            if c.status in (Status.FAIL, Status.BLOCKED):
                add("block", c)
            elif c.status == Status.WARN:
                add("remark", c)

    if any(r["level"] == "block" for r in reasons):
        verdict = Verdict.NO_GO
    elif reasons:
        verdict = Verdict.GO_WITH_REMARKS
    else:
        verdict = Verdict.GO
    if verdict == Verdict.GO and not device_ran and cfg.get_path("verdict.require_device", True):
        verdict = Verdict.GO_WITH_REMARKS
        reasons.append({"level": "remark", "id": "DV00", "title": "Устройство", "category": "device",
                        "text": "Выполнен только статический анализ, приложение не запускалось."})
    reasons.sort(key=lambda r: 0 if r["level"] == "block" else 1)
    return verdict, reasons
