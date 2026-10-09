from qa_tool.apk.apk import analyze_apk
from qa_tool.models import Status
from qa_tool.static_checks import run_static_checks


def by_id(results):
    return {r.id: r for r in results}


def test_clean_release_build_passes(apk, cfg):
    r = by_id(run_static_checks(analyze_apk(apk()), cfg(project={"expected_app_id": "com.demo.shop"})))
    fails = [x for x in r.values() if x.status == Status.FAIL]
    assert not fails, [(f.id, f.details) for f in fails]
    assert r["S01"].status == Status.PASS
    assert r["D00"].status == Status.SKIP  # нет прошлой сборки


def test_release_problems(apk, cfg):
    info = analyze_apk(apk(debuggable=True, test_only=True, native_align=4096, target_sdk=35,
                           extra_strings=["https://api.staging.x.example/", "-----BEGIN PRIVATE KEY-----",
                                          "Lleakcanary/LeakCanary;"], debug_cert=True))
    r = by_id(run_static_checks(info, cfg(project={"expected_app_id": "com.other.app"}), expect_version="9.9"))
    for cid in ("S01", "S02", "S04", "S05", "S06", "S07", "S13", "S14", "S15", "S16"):
        assert r[cid].status == Status.FAIL, (cid, r[cid].details)


def test_debug_build_is_lenient(apk, cfg):
    info = analyze_apk(apk(debuggable=True, debug_cert=True, cleartext=True))
    r = by_id(run_static_checks(info, cfg(project={"build_type": "debug"})))
    assert r["S05"].status == Status.INFO
    assert r["S04"].status == Status.PASS
    assert r["S08"].status == Status.INFO


def test_severity_override(apk, cfg):
    info = analyze_apk(apk(allow_backup=True))
    r = by_id(run_static_checks(info, cfg(static={"severity_overrides": {"S10": "INFO"}})))
    assert r["S10"].status == Status.INFO and r["S10"].extra["original_status"] == "WARN"


def test_compare_with_previous(apk, cfg):
    old = analyze_apk(apk("old.apk", version_code=20, padding_kb=100)).to_dict()
    new = analyze_apk(apk("new.apk", version_code=10, padding_kb=300,
                          permissions=["android.permission.INTERNET", "android.permission.CAMERA",
                                       "android.permission.POST_NOTIFICATIONS", "android.permission.READ_CONTACTS"]))
    r = by_id(run_static_checks(new, cfg(), prev=old))
    assert r["D01"].status == Status.FAIL               # versionCode уменьшился
    assert r["D03"].status == Status.WARN               # новое опасное разрешение
    assert "+ android.permission.READ_CONTACTS" in r["D03"].items
    assert r["D04"].status == Status.WARN               # вырос размер
