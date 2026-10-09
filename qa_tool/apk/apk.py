"""Сборка всей информации об APK в один объект ApkInfo."""
from __future__ import annotations

import hashlib
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .arsc import ResourceTable, parse_arsc
from .axml import AxmlError, ResRef, XmlElement, parse_axml
from .dex import CodeScan, scan_code
from .native import NativeInfo, analyze_native
from .signing import SigningInfo, analyze_signing

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA", "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS", "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.ADD_VOICEMAIL", "android.permission.USE_SIP",
    "android.permission.BODY_SENSORS", "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.ACTIVITY_RECOGNITION", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED", "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES", "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT", "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.UWB_RANGING", "android.permission.ACCESS_MEDIA_LOCATION",
}
# Особые разрешения, которые часто вызывают вопросы при ревью Google Play
SENSITIVE_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.USE_FULL_SCREEN_INTENT", "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.PACKAGE_USAGE_STATS", "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
}


@dataclass
class Component:
    kind: str
    name: str
    exported: bool
    explicit_exported: bool | None
    has_intent_filter: bool
    permission: str
    launcher: bool = False
    actions: list[str] = field(default_factory=list)


@dataclass
class NetworkConfig:
    file: str = ""
    base_cleartext: bool | None = None
    cleartext_domains: list[str] = field(default_factory=list)
    trusts_user_certs: bool = False
    debug_overrides_user_certs: bool = False


@dataclass
class ApkInfo:
    path: str
    file_name: str
    size_bytes: int
    sha256: str
    package: str = ""
    version_code: int | None = None
    version_name: str = ""
    label: str = ""
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    debuggable: bool = False
    test_only: bool = False
    allow_backup: bool | None = None
    uses_cleartext: bool | None = None
    extract_native_libs: bool | None = None
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    launcher_activity: str = ""
    locales: list[str] = field(default_factory=list)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    signing: SigningInfo = field(default_factory=SigningInfo)
    native: NativeInfo = field(default_factory=NativeInfo)
    code: CodeScan = field(default_factory=CodeScan)
    dex_count: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / 1024 / 1024, 2)

    @property
    def dangerous_permissions(self) -> list[str]:
        return [p for p in self.permissions if p in DANGEROUS_PERMISSIONS]

    @property
    def sensitive_permissions(self) -> list[str]:
        return [p for p in self.permissions if p in SENSITIVE_PERMISSIONS]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["size_mb"] = self.size_mb
        d["code"]["urls"] = {h: sorted(s) for h, s in self.code.urls.items()}
        d["signing"]["schemes"] = self.signing.schemes
        d["dangerous_permissions"] = self.dangerous_permissions
        return d


def _full_name(name: Any, package: str) -> str:
    name = str(name or "")
    if name.startswith("."):
        return package + name
    if name and "." not in name:
        return f"{package}.{name}"
    return name


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _as_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _parse_network_config(zf: zipfile.ZipFile, path: str) -> NetworkConfig:
    nc = NetworkConfig(file=path)
    try:
        root = parse_axml(zf.read(path))
    except (KeyError, AxmlError):
        return nc
    base = root.find("base-config")
    if base is not None:
        v = base.get("cleartextTrafficPermitted")
        nc.base_cleartext = v if isinstance(v, bool) else None
        for anchors in base.iter("certificates"):
            if anchors.get("src") == "user":
                nc.trusts_user_certs = True
    for dc in root.find_all("domain-config"):
        if dc.get("cleartextTrafficPermitted") is True:
            nc.cleartext_domains += [d.text or "?" for d in dc.find_all("domain")]
        for c in dc.iter("certificates"):
            if c.get("src") == "user":
                nc.trusts_user_certs = True
    dbg = root.find("debug-overrides")
    if dbg is not None:
        nc.debug_overrides_user_certs = any(c.get("src") == "user" for c in dbg.iter("certificates"))
    return nc


def analyze_apk(path: str | Path) -> ApkInfo:
    p = Path(path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Файл не найден: {p}")
    info = ApkInfo(path=str(p), file_name=p.name, size_bytes=p.stat().st_size, sha256=_sha256(p))
    try:
        zf = zipfile.ZipFile(p)
    except zipfile.BadZipFile as e:
        raise ValueError(f"{p.name} не является APK (ZIP повреждён): {e}") from e

    with zf:
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            raise ValueError(f"{p.name}: нет AndroidManifest.xml — это не APK (AAB/архив?)")
        table = ResourceTable()
        if "resources.arsc" in names:
            try:
                table = parse_arsc(zf.read("resources.arsc"))
                info.locales = table.string_locales
            except Exception as e:  # noqa: BLE001
                info.errors.append(f"resources.arsc: {e}")
        manifest = parse_axml(zf.read("AndroidManifest.xml"))
        _fill_from_manifest(info, manifest, table)

        nsc = manifest.find("application")
        nsc_ref = nsc.get("networkSecurityConfig") if nsc is not None else None
        if isinstance(nsc_ref, ResRef):
            resolved = table.resolve(nsc_ref)
            if isinstance(resolved, str) and resolved in names:
                info.network = _parse_network_config(zf, resolved)
            else:
                info.network = NetworkConfig(file=str(nsc_ref))

        info.signing = analyze_signing(str(p), zf)
        info.native = analyze_native(str(p), zf)
        info.code = scan_code(zf)
        info.dex_count = info.code.dex_count
    return info


def _fill_from_manifest(info: ApkInfo, m: XmlElement, table: ResourceTable) -> None:
    info.package = str(m.get("package", ""))
    info.version_code = _as_int(table.resolve(m.get("versionCode")))
    info.version_name = str(table.resolve(m.get("versionName", "")) or "")
    info.compile_sdk = _as_int(m.get("compileSdkVersion"))
    sdk = m.find("uses-sdk")
    if sdk is not None:
        info.min_sdk = _as_int(table.resolve(sdk.get("minSdkVersion")))
        info.target_sdk = _as_int(table.resolve(sdk.get("targetSdkVersion")))
    if info.min_sdk is None:
        info.min_sdk = 1
    if info.target_sdk is None:
        info.target_sdk = info.min_sdk

    perms = []
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for el in m.find_all(tag):
            n = el.get("name")
            if n and str(n) not in perms:
                perms.append(str(n))
    info.permissions = sorted(perms)

    app = m.find("application")
    if app is None:
        return
    info.label = str(table.resolve(app.get("label", "")) or "")
    info.debuggable = table.resolve(app.get("debuggable")) is True
    info.test_only = table.resolve(app.get("testOnly")) is True
    ab = table.resolve(app.get("allowBackup"))
    info.allow_backup = ab if isinstance(ab, bool) else None
    uc = table.resolve(app.get("usesCleartextTraffic"))
    info.uses_cleartext = uc if isinstance(uc, bool) else None
    en = table.resolve(app.get("extractNativeLibs"))
    info.extract_native_libs = en if isinstance(en, bool) else None

    for el in app.children:
        if el.tag not in COMPONENT_TAGS:
            continue
        if table.resolve(el.get("enabled")) is False:
            continue
        name = _full_name(el.get("name"), info.package)
        filters = el.find_all("intent-filter")
        actions = [str(a.get("name")) for f in filters for a in f.find_all("action")]
        categories = [str(c.get("name")) for f in filters for c in f.find_all("category")]
        explicit = table.resolve(el.get("exported"))
        explicit = explicit if isinstance(explicit, bool) else None
        if explicit is not None:
            exported = explicit
        elif el.tag == "provider":
            exported = (info.target_sdk or 0) < 17
        else:
            exported = bool(filters)
        launcher = ("android.intent.action.MAIN" in actions
                    and "android.intent.category.LAUNCHER" in categories)
        comp = Component(
            kind=el.tag, name=name, exported=exported, explicit_exported=explicit,
            has_intent_filter=bool(filters), permission=str(el.get("permission") or ""),
            launcher=launcher, actions=actions,
        )
        info.components.append(comp)
        if launcher and not info.launcher_activity and el.tag in ("activity", "activity-alias"):
            info.launcher_activity = name
