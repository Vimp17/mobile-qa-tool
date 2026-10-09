import os
import zipfile
from pathlib import Path

import pytest

from qa_tool.apk.apk import analyze_apk
from qa_tool.apk.axml import parse_axml
from qa_tool.apk.dex import dex_strings
from qa_tool.apk.native import elf_min_load_align
from qa_tool.demo import encode_axml, encode_dex, encode_elf64


def test_axml_roundtrip():
    data = encode_axml({"tag": "manifest", "attrs": {"package": "a.b", "versionCode": 7, "versionName": "1.0"},
                        "children": [{"tag": "application", "attrs": {"debuggable": True, "label": "X"}}]})
    root = parse_axml(data)
    assert root.tag == "manifest"
    assert root.get("package") == "a.b"
    assert root.get("versionCode") == 7
    app = root.find("application")
    assert app.get("debuggable") is True and app.get("label") == "X"


def test_dex_strings_and_elf():
    assert set(dex_strings(encode_dex(["https://a.example/x", "Lfoo/Bar;"]))) == {"https://a.example/x", "Lfoo/Bar;"}
    assert elf_min_load_align(encode_elf64(4096)) == 4096
    assert elf_min_load_align(encode_elf64(16384)) == 16384
    assert elf_min_load_align(b"not elf") is None


def test_analyze_synthetic(apk):
    p = apk(version_code=12, version_name="2.1", debuggable=True, cleartext=True, exported_receiver=True,
            native_align=4096, extra_strings=["https://api.staging.x.example/", "AKIAABCDEFGHIJKLMNOP"])
    info = analyze_apk(p)
    assert info.package == "com.demo.shop"
    assert (info.version_code, info.version_name) == (12, "2.1")
    assert info.min_sdk == 24 and info.target_sdk == 36
    assert info.debuggable and info.uses_cleartext is True
    assert info.launcher_activity == "com.demo.shop.ui.MainActivity"
    assert any(c.name == "com.demo.shop.push.PromoReceiver" and c.exported for c in info.components)
    assert info.native.abis == ["arm64-v8a", "x86_64"] and len(info.native.not_16k()) == 2
    assert "api.staging.x.example" in info.code.urls
    assert any(s[0] == "AWS Access Key ID" for s in info.code.secrets)
    assert info.signing.v1 and info.signing.certs and not info.signing.certs[0].is_debug
    assert "android.permission.CAMERA" in info.dangerous_permissions


def test_not_an_apk(tmp_path):
    z = tmp_path / "x.apk"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("hello.txt", "x")
    with pytest.raises(ValueError):
        analyze_apk(z)
    bad = tmp_path / "bad.apk"
    bad.write_text("nope")
    with pytest.raises(ValueError):
        analyze_apk(bad)


REAL = os.getenv("QA_REAL_APKS", "")


@pytest.mark.skipif(not REAL, reason="укажите QA_REAL_APKS=путь1.apk:путь2.apk для проверки на реальных сборках")
def test_real_apks():
    for p in REAL.split(os.pathsep):
        info = analyze_apk(Path(p))
        assert info.package and info.version_code and info.target_sdk
        assert info.signing.signed
        assert info.launcher_activity
