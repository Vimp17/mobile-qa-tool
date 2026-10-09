"""Демо-режим и генератор синтетических APK (используется и в тестах).

`qa demo` собирает две версии выдуманного приложения, прогоняет их через настоящий
статический анализ и подставляет смоделированные результаты устройства — так можно
посмотреть отчёт целиком без эмулятора.
"""
from __future__ import annotations

import io
import struct
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .apk.axml import ANDROID_ATTR_IDS
from .models import CheckResult, Status

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ATTR_TO_ID = {v: k for k, v in ANDROID_ATTR_IDS.items()}


# ---------------------------------------------------------------- AXML writer
class _Pool:
    def __init__(self):
        self.items: list[str] = []
        self.index: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s not in self.index:
            self.index[s] = len(self.items)
            self.items.append(s)
        return self.index[s]

    def encode(self) -> bytes:
        data = b""
        offsets = []
        for s in self.items:
            offsets.append(len(data))
            enc = s.encode("utf-16-le")
            data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        header_size = 28
        strings_start = header_size + 4 * len(self.items)
        body = struct.pack(f"<{len(offsets)}I", *offsets) + data
        return struct.pack("<HHIIIIII", 0x0001, header_size, header_size + len(body),
                           len(self.items), 0, 0, strings_start, 0) + body


def encode_axml(root: dict) -> bytes:
    """root = {"tag": str, "attrs": {name: value}, "children": [...]} ; атрибуты — android:*."""
    pool = _Pool()
    # Сначала имена атрибутов с resource id (так требует формат resource map)
    attr_names: list[str] = []

    def collect(el):
        for k in el.get("attrs", {}):
            if k in _ATTR_TO_ID and k not in attr_names:
                attr_names.append(k)
        for c in el.get("children", []):
            collect(c)
    collect(root)
    for n in attr_names:
        pool.add(n)
    ns_idx = pool.add(ANDROID_NS)
    prefix_idx = pool.add("android")

    chunks: list[bytes] = []

    def emit(el):
        name_idx = pool.add(el["tag"])
        attrs = []
        for k, v in el.get("attrs", {}).items():
            a_ns = ns_idx if k in _ATTR_TO_ID else 0xFFFFFFFF
            a_name = pool.add(k)
            if isinstance(v, bool):
                raw, dtype, val = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                raw, dtype, val = 0xFFFFFFFF, 0x10, v & 0xFFFFFFFF
            else:
                si = pool.add(str(v))
                raw, dtype, val = si, 0x03, si
            attrs.append(struct.pack("<IIIHBBI", a_ns, a_name, raw, 8, 0, dtype, val))
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_idx, 20, 20, len(attrs), 0, 0, 0)
        body = ext + b"".join(attrs)
        chunks.append(struct.pack("<HHIII", 0x0102, 16, 16 + len(body), 1, 0xFFFFFFFF) + body)
        for c in el.get("children", []):
            emit(c)
        chunks.append(struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx))

    emit(root)
    start_ns = struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, prefix_idx, ns_idx)
    end_ns = struct.pack("<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, prefix_idx, ns_idx)
    res_ids = [_ATTR_TO_ID[n] for n in attr_names]
    res_map = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(res_ids)) + struct.pack(f"<{len(res_ids)}I", *res_ids)
    sp = pool.encode()  # после emit — все строки уже в пуле
    body = sp + res_map + start_ns + b"".join(chunks) + end_ns
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# ---------------------------------------------------------------- DEX / ELF
def encode_dex(strings: list[str]) -> bytes:
    strings = sorted(set(strings))
    header = bytearray(0x70)
    header[:8] = b"dex\n035\x00"
    ids_off = 0x70
    data_off = ids_off + 4 * len(strings)
    ids, data = [], b""
    for s in strings:
        ids.append(data_off + len(data))
        b = s.encode("utf-8")
        n = len(s)
        uleb = b""
        while True:
            byte = n & 0x7F
            n >>= 7
            uleb += bytes([byte | (0x80 if n else 0)])
            if not n:
                break
        data += uleb + b + b"\x00"
    struct.pack_into("<II", header, 0x38, len(strings), ids_off)
    return bytes(header) + struct.pack(f"<{len(ids)}I", *ids) + data


def encode_elf64(load_align: int) -> bytes:
    eh = bytearray(64)
    eh[:4] = b"\x7fELF"
    eh[4], eh[5], eh[6] = 2, 1, 1
    struct.pack_into("<HHI", eh, 16, 3, 183, 1)            # ET_DYN, EM_AARCH64
    struct.pack_into("<Q", eh, 0x20, 64)                   # e_phoff
    struct.pack_into("<HHHHHH", eh, 0x34, 64, 56, 2, 64, 0, 0)
    ph = b""
    for _ in range(2):
        ph += struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0x1000, 0x1000, load_align)
    return bytes(eh) + ph + b"\x00" * 256


# ---------------------------------------------------------------- подпись (v1)
_SIG_CACHE: dict[bool, tuple[bytes, bytes]] = {}


def _debug_signature(debug: bool = True) -> tuple[bytes, bytes]:
    """Один ключ на процесс — чтобы версии демо-приложения были подписаны одинаково."""
    if debug not in _SIG_CACHE:
        _SIG_CACHE[debug] = _make_signature(debug)
    return _SIG_CACHE[debug]


def _make_signature(debug: bool) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cn = "Android Debug" if debug else "Demo Release"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android" if debug else "Demo Inc"),
                      x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365 * 25)).sign(key, hashes.SHA256()))
    sf = b"Signature-Version: 1.0\r\nCreated-By: qa-tool demo\r\n\r\n"
    p7 = (pkcs7.PKCS7SignatureBuilder().set_data(sf).add_signer(cert, key, hashes.SHA256())
          .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    return sf, p7


def build_apk(path: Path, *, package="com.demo.shop", version_code=140, version_name="1.4.0",
              label="Demo Shop", min_sdk=24, target_sdk=36, debuggable=False, allow_backup=False,
              cleartext=False, permissions: list[str] | None = None, extra_strings: list[str] | None = None,
              exported_receiver=False, native_align: int | None = None, signed: bool = True,
              debug_cert: bool = False, padding_kb: int = 0, test_only=False) -> Path:
    permissions = permissions or ["android.permission.INTERNET", "android.permission.CAMERA",
                                  "android.permission.POST_NOTIFICATIONS"]
    app_children: list[dict] = [{
        "tag": "activity", "attrs": {"name": ".ui.MainActivity", "exported": True},
        "children": [{"tag": "intent-filter", "children": [
            {"tag": "action", "attrs": {"name": "android.intent.action.MAIN"}},
            {"tag": "category", "attrs": {"name": "android.intent.category.LAUNCHER"}}]}],
    }, {
        "tag": "activity", "attrs": {"name": ".ui.ProductActivity", "exported": False},
    }]
    if exported_receiver:
        app_children.append({"tag": "receiver", "attrs": {"name": ".push.PromoReceiver", "exported": True},
                             "children": [{"tag": "intent-filter", "children": [
                                 {"tag": "action", "attrs": {"name": "com.demo.shop.PROMO"}}]}]})
    app_attrs: dict[str, Any] = {"label": label, "allowBackup": allow_backup}
    if debuggable:
        app_attrs["debuggable"] = True
    if cleartext:
        app_attrs["usesCleartextTraffic"] = True
    if test_only:
        app_attrs["testOnly"] = True
    manifest = {
        "tag": "manifest",
        "attrs": {"versionCode": version_code, "versionName": version_name, "compileSdkVersion": target_sdk,
                  "package": package},
        "children": [{"tag": "uses-sdk", "attrs": {"minSdkVersion": min_sdk, "targetSdkVersion": target_sdk}}]
        + [{"tag": "uses-permission", "attrs": {"name": p}} for p in permissions]
        + [{"tag": "application", "attrs": app_attrs, "children": app_children}],
    }
    strings = ["Lcom/demo/shop/ui/MainActivity;", "https://api.demo-shop.example/v2/", "https://cdn.demo-shop.example/img",
               "https://firebase-settings.crashlytics.com/spi/v2", "http://schemas.android.com/apk/res/android"]
    strings += extra_strings or []
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", encode_axml(manifest))
        z.writestr("classes.dex", encode_dex(strings))
        if native_align:
            z.writestr("lib/arm64-v8a/libimage.so", encode_elf64(native_align))
            z.writestr("lib/x86_64/libimage.so", encode_elf64(native_align))
        if padding_kb:
            import os
            z.writestr("assets/catalog.bin", os.urandom(padding_kb * 1024), compress_type=zipfile.ZIP_STORED)
        if signed:
            sf, p7 = _debug_signature(debug_cert)
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
            z.writestr("META-INF/CERT.SF", sf)
            z.writestr("META-INF/CERT.RSA", p7)
    return path


# ---------------------------------------------------------------- фейковое устройство
def _font(size: int):
    from PIL import ImageFont
    for cand in ("DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "arial.ttf",
                 "C:/Windows/Fonts/arial.ttf", "/System/Library/Fonts/Supplemental/Arial.ttf",
                 "/Library/Fonts/Arial.ttf"):
        try:
            return ImageFont.truetype(cand, size)
        except OSError:
            continue
    return None


def _fake_screen(path: Path, title: str, lines: list[str], accent=(37, 99, 235), error: str = "") -> None:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return
    w, h = 540, 1140
    img = Image.new("RGB", (w, h), (248, 249, 251))
    d = ImageDraw.Draw(img)
    big, small = _font(30), _font(22)
    if big is None:  # без шрифта с кириллицей рисуем только плашки
        title, lines, error = "", ["" for _ in lines], ("!" if error else "")
    d.rectangle([0, 0, w, 60], fill=(20, 20, 24))
    d.rectangle([0, 60, w, 170], fill=accent)
    d.text((28, 95), title, fill=(255, 255, 255), font=big)
    y = 210
    for ln in lines:
        d.rounded_rectangle([24, y, w - 24, y + 110], radius=18, fill=(255, 255, 255), outline=(225, 228, 233))
        d.rectangle([44, y + 22, 124, y + 88], fill=(226, 232, 240))
        d.text((144, y + 26), ln, fill=(30, 30, 35), font=small)
        d.text((144, y + 58), "1 990 руб." if big else "", fill=(100, 106, 115), font=small)
        y += 130
    if error:
        d.rounded_rectangle([40, h // 2 - 90, w - 40, h // 2 + 90], radius=16, fill=(255, 255, 255), outline=(198, 47, 47), width=3)
        d.text((70, h // 2 - 50), "Приложение Demo Shop остановлено" if big else "", fill=(198, 47, 47), font=small)
        d.text((70, h // 2 - 10), error, fill=(60, 60, 60), font=small)
    d.rectangle([0, h - 70, w, h], fill=(255, 255, 255))
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path)


DEMO_CRASH = """FATAL EXCEPTION: main
Process: com.demo.shop, PID: 8812
java.lang.NullPointerException: Attempt to invoke virtual method 'java.lang.String com.demo.shop.model.Promo.getTitle()' on a null object reference
\tat com.demo.shop.ui.promo.PromoBannerView.bind(PromoBannerView.kt:42)
\tat com.demo.shop.ui.catalog.CatalogFragment.onPromoLoaded(CatalogFragment.kt:118)
\tat com.demo.shop.ui.catalog.CatalogFragment.access$onPromoLoaded(CatalogFragment.kt:1)
\tat androidx.lifecycle.LiveData.considerNotify(LiveData.java:133)
\tat android.os.Handler.handleCallback(Handler.java:959)
\tat android.os.Looper.loop(Looper.java:337)
\tat android.app.ActivityThread.main(ActivityThread.java:9496)"""


def fake_device_runner(variant: str):
    """Возвращает device_runner для pipeline.run_check с заранее заданным сценарием."""
    from .device.adb import DeviceInfo
    from .device.logcat import Crash
    from .device.smoke import DeviceStage

    def runner(apk, cfg, run_dir: Path, opts) -> DeviceStage:
        st = DeviceStage()
        st.device = DeviceInfo(serial="emulator-5554", state="device", model="sdk gphone64 x86 64",
                               android="15", sdk=35, abis=["x86_64", "arm64-v8a"], is_emulator=True, screen="1080x2400")
        dev_dir = run_dir / "device"
        good = variant == "good"
        _fake_screen(dev_dir / "screens/01_after_launch.png", "Каталог", ["Кроссовки Run 2", "Рюкзак City", "Куртка Wind"])
        (dev_dir / "logcat.txt").parent.mkdir(parents=True, exist_ok=True)
        (dev_dir / "logcat.txt").write_text("demo logcat\n" + ("" if good else DEMO_CRASH), encoding="utf-8")
        st.logcat_file = "device/logcat.txt"
        cs = 1240 if good else 2380
        st.metrics = {"install_sec": 3.4, "cold_start_ms": cs, "cold_start_runs": [cs + 40, cs, cs - 35],
                      "memory_pss_mb": 142.7 if good else 188.3}
        c = lambda *a, **k: CheckResult(*a, category="device", **k)  # noqa: E731
        st.checks += [
            c("DV00", "Устройство", Status.PASS, f"{st.device.title}, экран 1080x2400"),
            c("DV01", "Установка", Status.PASS, "Чистая установка за 3.4 с, разрешения выданы (-g)", duration_sec=3.4),
            c("DV02", "Холодный старт", Status.PASS if good else Status.WARN,
              f"Медиана {cs} мс по 3 запускам. Порог: предупреждение 2000 мс, провал 5000 мс."),
            c("DV03", "Приложение работает после старта", Status.PASS,
              "Процесс жив (pid 8812), экран приложения на переднем плане.", evidence=["device/screens/01_after_launch.png"]),
            c("DV04", "Память после старта (PSS)", Status.INFO, f"{st.metrics['memory_pss_mb']} МБ"),
        ]
        # Maestro
        flows = [("SMOKE-001", "Запуск и онбординг", "P0", Status.PASS, ""),
                 ("SMOKE-002", "Логин по телефону", "P0", Status.PASS, ""),
                 ("SMOKE-003", "Каталог и карточка товара", "P0", Status.PASS if good else Status.FAIL,
                  "" if good else "Assertion is false: \"Добавить в корзину\" is visible"),
                 ("SMOKE-004", "Поиск", "P1", Status.PASS if good else Status.FLAKY,
                  "" if good else "Упал, но прошёл при перезапуске №1. Первая ошибка: Element not found: Id matching regex: search_input"),
                 ("SMOKE-005", "Корзина и оформление", "P0", Status.PASS, ""),
                 ("SMOKE-006", "Выход из аккаунта", "P1", Status.PASS, "")]
        for tid, name, prio, status, msg in flows:
            ev = []
            if status == Status.FAIL:
                p = run_dir / "maestro/output/screenshot-❌-(SMOKE-003 Каталог и карточка товара).png"
                _fake_screen(p, "Кроссовки Run 2", ["Размер 42", "Цвет: чёрный"], error="")
                ev = [str(p.relative_to(run_dir)).replace("\\", "/")]
            st.checks.append(CheckResult(tid, name, status, msg, category="maestro", priority=prio,
                                         duration_sec={"P0": 14.2, "P1": 8.7}[prio], evidence=ev))
        if good:
            st.checks.append(c("DV05", "Monkey-стресс", Status.PASS, "500 случайных действий без падений.", duration_sec=61.0))
            st.checks.append(c("DV09", "Крэши и ANR в logcat", Status.PASS, "Падений приложения не найдено.", evidence=[st.logcat_file]))
        else:
            _fake_screen(dev_dir / "screens/02_after_monkey.png", "Каталог", ["Кроссовки Run 2"], error="NullPointerException")
            st.checks.append(c("DV05", "Monkey-стресс", Status.FAIL,
                               "крэш после 214 из 500 случайных действий (seed 42 — можно воспроизвести).",
                               duration_sec=27.5, evidence=["device/screens/02_after_monkey.png"]))
            st.crashes = [Crash("java", "java.lang.NullPointerException: Attempt to invoke virtual method "
                                "'java.lang.String com.demo.shop.model.Promo.getTitle()' on a null object reference",
                                "10-09 15:42:17.204", "monkey", DEMO_CRASH)]
            st.checks.append(c("DV09", "Крэши и ANR в logcat", Status.FAIL, "Найдено: 1. Полные стектрейсы — в разделе «Крэши».",
                               items=["[monkey] Крэш (Java/Kotlin): java.lang.NullPointerException: … Promo.getTitle() …"],
                               evidence=[st.logcat_file]))
        return st
    return runner


def run_demo(out_dir: Path, log=print) -> dict:
    from .config import load_config
    from .pipeline import RunOptions, run_check

    out_dir = out_dir.resolve()
    cfg = load_config(overrides={
        "project": {"name": "Demo Shop", "environment": "STAGE", "expected_app_id": "com.demo.shop", "build_type": "release"},
        "paths": {"runs_dir": str(out_dir / "qa_runs")},
        # Синтетический APK подписан только схемой v1 — в демо это не считаем замечанием
        "static": {"severity_overrides": {"S03": "INFO"}},
        "google_sheets": {"enabled": False}, "telegram": {"enabled": False},
    })
    apks = out_dir / "apks"
    v1 = build_apk(apks / "demo-shop-1.4.0.apk", version_code=140, version_name="1.4.0", padding_kb=900)
    v2 = build_apk(apks / "demo-shop-1.5.0.apk", version_code=150, version_name="1.5.0", padding_kb=1150,
                   permissions=["android.permission.INTERNET", "android.permission.CAMERA",
                                "android.permission.POST_NOTIFICATIONS", "android.permission.ACCESS_FINE_LOCATION"],
                   extra_strings=["https://api.staging.demo-shop.example/v2/", "http://promo.demo-shop.example/banner",
                                  "Lleakcanary/LeakCanary;", "AIzaSyD3m0K3yF0rF1reba5eDem0NotReal12345"],
                   exported_receiver=True, native_align=4096, allow_backup=True)
    log("— Прогон 1: предыдущая версия 1.4.0 (эталон для сравнения)")
    run_check(v1, cfg, RunOptions(), log=lambda *_: None, device_runner=fake_device_runner("good"))
    log("— Прогон 2: новая сборка 1.5.0")
    return run_check(v2, cfg, RunOptions(), log=log, device_runner=fake_device_runner("bad"))
