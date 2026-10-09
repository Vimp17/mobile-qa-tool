from qa_tool.device.logcat import parse_crashes, parse_monkey
from qa_tool.maestro import load_flows, parse_junit
from qa_tool.models import Status

LOG = """10-09 10:00:00.000  1000  1000 I QA_TOOL : STAGE: launch
10-09 10:00:01.000  4321  4321 E AndroidRuntime: FATAL EXCEPTION: main
10-09 10:00:01.000  4321  4321 E AndroidRuntime: Process: com.other.app, PID: 4321
10-09 10:00:01.000  4321  4321 E AndroidRuntime: java.lang.RuntimeException: not ours
10-09 10:00:02.000  1000  1000 I QA_TOOL : STAGE: monkey
10-09 10:00:03.000  5555  5555 E AndroidRuntime: FATAL EXCEPTION: main
10-09 10:00:03.000  1200  1200 I SomethingElse: interleaved line
10-09 10:00:03.000  5555  5555 E AndroidRuntime: Process: com.demo.shop, PID: 5555
10-09 10:00:03.000  5555  5555 E AndroidRuntime: java.lang.NullPointerException: npe
10-09 10:00:03.000  5555  5555 E AndroidRuntime: \tat com.demo.shop.A.b(A.kt:1)
10-09 10:00:04.000  1500  1520 E ActivityManager: ANR in com.demo.shop (com.demo.shop/.Main)
10-09 10:00:04.000  1500  1520 E ActivityManager: PID: 5555
10-09 10:00:04.000  1500  1520 E ActivityManager: Reason: Input dispatching timed out
10-09 10:00:05.000  6000  6010 F libc    : Fatal signal 11 (SIGSEGV), code 1, fault addr 0x0 in tid 6010 (RenderThread), pid 6000 (com.demo.shop)
10-09 10:00:05.100  6100  6100 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-09 10:00:05.100  6100  6100 F DEBUG   : pid: 6000, tid: 6010, name: RenderThread  >>> com.demo.shop <<<
"""


def test_logcat_crashes():
    crashes = parse_crashes(LOG, "com.demo.shop")
    kinds = [c.kind for c in crashes]
    assert kinds == ["java", "anr", "native"]
    java = crashes[0]
    assert java.title.startswith("java.lang.NullPointerException") and java.stage == "monkey"
    assert "A.kt:1" in java.text
    assert crashes[1].title.startswith("Reason: Input dispatching")
    assert ">>> com.demo.shop <<<" in crashes[2].text


def test_monkey():
    r = parse_monkey("// CRASH: com.demo.shop (pid 1)\n** Monkey aborted due to error.\nEvents injected: 12", "com.demo.shop")
    assert r["crash"] and r["injected"] == 12
    r = parse_monkey("Events injected: 500\n// Monkey finished", "com.demo.shop")
    assert not r["crash"] and r["finished"]


def test_junit_and_flows(tmp_path, flows):
    metas = load_flows(flows)
    assert {m.test_id for m in metas} == {"SMOKE-001", "SMOKE-002", "SMOKE-003"}
    j = tmp_path / "j.xml"
    j.write_text('<testsuite><testcase name="a" time="1.5"/><testcase name="b"><failure message="boom"/></testcase>'
                 '<testcase name="c"><skipped/></testcase></testsuite>')
    cases = parse_junit(j)
    assert [c.status for c in cases] == [Status.PASS, Status.FAIL, Status.BLOCKED]
    assert cases[1].message == "boom"
