import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qa_tool.config import load_config  # noqa: E402
from qa_tool.demo import build_apk  # noqa: E402

FAKE_BIN = Path(__file__).parent / "fake_bin"

FLOWS = {
    "launch.yaml": ("SMOKE-001 Launch", "SMOKE-001", "P0"),
    "home.yaml": ("SMOKE-002 Home screen", "SMOKE-002", "P1"),
    "logout.yaml": ("SMOKE-003 Logout", "SMOKE-003", "P0"),
}


@pytest.fixture
def cfg(tmp_path):
    def make(**overrides):
        base = {"paths": {"runs_dir": str(tmp_path / "runs"), "flows_dir": str(tmp_path / "flows")},
                "device": {"launch_runs": 2, "settle_sec": 0, "monkey_events": 50, "boot_timeout_sec": 5}}
        for k, v in overrides.items():
            base.setdefault(k, {}).update(v)
        return load_config(path=_empty_cfg(tmp_path), overrides=base)
    return make


def _empty_cfg(tmp_path):
    p = tmp_path / "qa.yaml"
    if not p.exists():
        p.write_text("project:\n  name: Test\n", encoding="utf-8")
    return p


@pytest.fixture
def apk(tmp_path):
    def make(name="app.apk", **kw):
        return build_apk(tmp_path / "apks" / name, **kw)
    return make


@pytest.fixture
def flows(tmp_path):
    d = tmp_path / "flows"
    d.mkdir(exist_ok=True)
    for fname, (name, tid, prio) in FLOWS.items():
        (d / fname).write_text(
            f"appId: ${{MAESTRO_APP_ID}}\nname: {name}\ntags: [smoke]\nproperties:\n  testCaseId: \"{tid}\"\n"
            f"  priority: \"{prio}\"\n---\n- launchApp\n", encoding="utf-8")
    return d


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("фейковые adb/maestro — shell-скрипты, на Windows не запускаются")
    for f in FAKE_BIN.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{FAKE_BIN}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_ADB_STATE", str(tmp_path / "adb_state"))
    monkeypatch.setenv("FAKE_MAESTRO_STATE", str(tmp_path / "maestro_state"))
    monkeypatch.setenv("FAKE_ADB_PKG", "com.demo.shop")

    def scenario(name="ok"):
        monkeypatch.setenv("FAKE_ADB_SCENARIO", name)
    scenario("ok")
    return scenario
