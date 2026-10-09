import json
import xml.etree.ElementTree as ET
from pathlib import Path

from qa_tool.cli import main
from qa_tool.integrations.sheets import export_to_sheets
from qa_tool.integrations.telegram import build_message
from qa_tool.pipeline import RunOptions, run_check

quiet = lambda *_: None  # noqa: E731


def checks(summary):
    return {c["id"]: c for c in summary["checks"]}


def test_full_run_ok_with_maestro(apk, cfg, flows, fake_tools):
    s = run_check(apk(), cfg(project={"expected_app_id": "com.demo.shop"}), RunOptions(), log=quiet)
    c = checks(s)
    assert c["DV00"]["status"] == "PASS"
    assert c["DV01"]["status"] == "PASS"
    assert c["DV02"]["status"] == "PASS" and s["metrics"]["cold_start_ms"] == 812
    assert c["DV03"]["status"] == "PASS" and c["DV03"]["evidence"]
    assert s["metrics"]["memory_pss_mb"] == 141.8
    assert c["DV05"]["status"] == "PASS"
    assert c["DV09"]["status"] == "PASS"
    # Maestro: SMOKE-002 (P1) падает всегда, SMOKE-003 (P0) — только первый раз
    assert c["SMOKE-001"]["status"] == "PASS"
    assert c["SMOKE-002"]["status"] == "FAIL" and c["SMOKE-002"]["priority"] == "P1"
    assert c["SMOKE-002"]["evidence"], "скриншот падения должен быть привязан к тесту"
    assert c["SMOKE-003"]["status"] == "FLAKY"
    # P1 упал, P0 нестабилен → с замечаниями, но не блокер
    assert s["verdict"] == "GO_WITH_REMARKS"
    run_dir = Path(s["run_dir"])
    for f in ("report.html", "summary.json", "junit_all.xml", "apk_info.json", "device/logcat.txt"):
        assert (run_dir / f).exists(), f
    ET.parse(run_dir / "junit_all.xml")
    assert (run_dir.parent / "history.csv").exists()
    html = (run_dir / "report.html").read_text(encoding="utf-8")
    assert "Принять с замечаниями" in html and "SMOKE-003" in html


def test_crash_means_no_go(apk, cfg, fake_tools):
    fake_tools("crash")
    s = run_check(apk(), cfg(), RunOptions(skip_maestro=True), log=quiet)
    c = checks(s)
    assert s["verdict"] == "NO_GO"
    assert c["DV05"]["status"] == "FAIL"
    assert c["DV09"]["status"] == "FAIL"
    kinds = sorted(x["kind"] for x in s["crashes"])
    assert kinds == ["anr", "java"]
    assert all(x["stage"] == "monkey" for x in s["crashes"])
    assert "IllegalStateException" in (Path(s["report_path"]).read_text(encoding="utf-8"))


def test_no_device_is_not_go(apk, cfg, fake_tools):
    fake_tools("nodevice")
    s = run_check(apk(), cfg(), RunOptions(), log=quiet)
    assert checks(s)["DV00"]["status"] == "BLOCKED"
    assert s["verdict"] == "GO_WITH_REMARKS"


def test_install_failure(apk, cfg, fake_tools):
    fake_tools("installfail")
    s = run_check(apk(), cfg(), RunOptions(), log=quiet)
    assert checks(s)["DV01"]["status"] == "FAIL"
    assert "INSTALL_FAILED_NO_MATCHING_ABIS" in checks(s)["DV01"]["details"]
    assert s["verdict"] == "NO_GO"


def test_static_only_and_history_diff(apk, cfg):
    conf = cfg()
    s1 = run_check(apk("a.apk", version_code=1), conf, RunOptions(skip_device=True), log=quiet)
    s2 = run_check(apk("b.apk", version_code=2), conf, RunOptions(skip_device=True), log=quiet)
    assert s1["prev_build"] is None
    assert s2["prev_build"]["version_code"] == 1
    assert checks(s2)["D01"]["status"] == "PASS"
    assert s2["verdict"] == "GO_WITH_REMARKS"  # без устройства — не «Принять»
    assert len(s2["history"]) == 2


class FakeWS:
    def __init__(self, title):
        self.title, self.rows = title, []

    def append_row(self, row, value_input_option=None):
        self.rows.append(row)

    def append_rows(self, rows, value_input_option=None):
        self.rows.extend(rows)

    def col_values(self, i):
        return [r[i - 1] for r in self.rows]

    def format(self, *a, **k):
        pass

    def freeze(self, *a, **k):
        pass


class FakeSheet:
    url = "https://docs.google.com/spreadsheets/d/XYZ"

    def __init__(self):
        self.ws = {}

    def worksheet(self, title):
        import gspread
        if title not in self.ws:
            raise gspread.WorksheetNotFound(title)
        return self.ws[title]

    def add_worksheet(self, title, rows, cols):
        self.ws[title] = FakeWS(title)
        return self.ws[title]


class FakeClient:
    def __init__(self):
        self.sheet = FakeSheet()

    def open_by_key(self, key):
        assert key == "XYZ"
        return self.sheet


def test_sheets_export(apk, cfg):
    import pytest
    pytest.importorskip("gspread")
    conf = cfg(google_sheets={"enabled": False, "spreadsheet": "https://docs.google.com/spreadsheets/d/XYZ/edit#gid=0"})
    s = run_check(apk(), conf, RunOptions(skip_device=True), log=quiet)
    client = FakeClient()
    url = export_to_sheets(s, conf, client=client)
    assert url.endswith("XYZ")
    runs = client.sheet.ws["Прогоны"].rows
    assert runs[0][0] == "ID прогона" and runs[1][0] == s["run_id"]
    assert runs[1][8] == "Принять с замечаниями"
    checks_ws = client.sheet.ws["Проверки"].rows
    assert len(checks_ws) == 1 + len(s["checks"])


def test_telegram_message(apk, cfg):
    s = run_check(apk(), cfg(), RunOptions(skip_device=True), log=quiet)
    msg = build_message(s)
    assert "Принять с замечаниями" in msg and "com.demo.shop" not in msg.split("\n")[0]


def test_cli_static_demo_init(tmp_path, apk, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "proj"]) == 0
    assert (tmp_path / "proj/qa.yaml").exists() and (tmp_path / "proj/.maestro/smoke/01_launch.yaml").exists()
    p = apk(debuggable=True)
    code = main(["-c", str(tmp_path / "proj/qa.yaml"), "static", str(p)])
    assert code == 2  # debuggable в release → «Не принимать» → код 2
    assert main(["-c", str(tmp_path / "proj/qa.yaml"), "static", str(p), "--fail-on", "never"]) == 0
    assert main(["-c", str(tmp_path / "proj/qa.yaml"), "history"]) == 0
    run_dir = next((tmp_path / "proj/qa_runs").glob("*/summary.json")).parent
    assert main(["-c", str(tmp_path / "proj/qa.yaml"), "report", str(run_dir)]) == 0
    assert main(["demo", "--out", str(tmp_path / "demo")]) == 0
    s = json.loads(next((tmp_path / "demo/qa_runs").glob("*1.5.0/summary.json")).read_text(encoding="utf-8"))
    assert s["verdict"] == "NO_GO"
