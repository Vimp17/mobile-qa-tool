"""Общие структуры данных: результат одной проверки, статусы, вердикт."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"
    FLAKY = "FLAKY"      # прошёл только после перезапуска
    BLOCKED = "BLOCKED"  # не смог выполниться (нет устройства, упала установка и т.п.)

    def __str__(self) -> str:  # pragma: no cover - удобство вывода
        return self.value


STATUS_ORDER = {
    Status.FAIL: 0, Status.BLOCKED: 1, Status.WARN: 2, Status.FLAKY: 3,
    Status.INFO: 4, Status.PASS: 5, Status.SKIP: 6,
}


class Verdict(str, Enum):
    GO = "GO"
    GO_WITH_REMARKS = "GO_WITH_REMARKS"
    NO_GO = "NO_GO"

    @property
    def title(self) -> str:
        return {
            Verdict.GO: "Принять",
            Verdict.GO_WITH_REMARKS: "Принять с замечаниями",
            Verdict.NO_GO: "Не принимать",
        }[self]


@dataclass
class CheckResult:
    """Одна строка отчёта: статическая проверка, шаг на устройстве или тест Maestro."""

    id: str
    title: str
    status: Status
    details: str = ""
    category: str = "static"          # static | device | maestro
    priority: str = ""                # P0/P1/P2 для тестов
    duration_sec: float | None = None
    items: list[str] = field(default_factory=list)       # список находок (разрешения, хосты, ...)
    evidence: list[str] = field(default_factory=list)    # пути к скриншотам/логам относительно папки прогона
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CheckResult":
        d = dict(d)
        d["status"] = Status(d["status"])
        return cls(**d)


def worst(statuses) -> Status | None:
    statuses = list(statuses)
    if not statuses:
        return None
    return min(statuses, key=lambda s: STATUS_ORDER[s])
