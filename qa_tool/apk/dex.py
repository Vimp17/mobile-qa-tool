"""Извлечение строк из classes*.dex: URL бэкендов, секреты, отладочные библиотеки."""
from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass, field
from urllib.parse import urlsplit


def _uleb128(data: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def dex_strings(data: bytes) -> list[str]:
    if data[:4] != b"dex\n":
        return []
    count, ids_off = struct.unpack_from("<II", data, 0x38)
    out: list[str] = []
    for i in range(count):
        try:
            str_off = struct.unpack_from("<I", data, ids_off + i * 4)[0]
            _n, p = _uleb128(data, str_off)
            end = data.index(b"\x00", p)
            # MUTF-8: для поиска URL/ключей достаточно обычного utf-8 с заменой
            out.append(data[p:end].decode("utf-8", errors="replace"))
        except (struct.error, ValueError, IndexError):
            continue
    return out


URL_RE = re.compile(r"\b(https?|wss?)://([A-Za-z0-9.\-_]+(?::\d+)?)(/[^\s\"'<>]*)?")

SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # (название, уровень: high|low, regex)
    ("Приватный ключ", "high", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("AWS Access Key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Stripe live secret", "high", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Telegram bot token", "high", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("Google API key", "low", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
]

# Библиотеки, которым не место в release-сборке (дескрипторы классов в dex).
DEBUG_LIBS = {
    "LeakCanary": "Lleakcanary/",
    "Chucker (HTTP-инспектор)": "Lcom/chuckerteam/chucker/",
    "Flipper": "Lcom/facebook/flipper/",
    "Stetho": "Lcom/facebook/stetho/",
    "Hyperion": "Lcom/willowtreeapps/hyperion/",
    "OkHttp MockWebServer": "Lokhttp3/mockwebserver/",
}


@dataclass
class CodeScan:
    dex_count: int = 0
    string_count: int = 0
    urls: dict[str, set[str]] = field(default_factory=dict)   # host -> {scheme}
    url_samples: dict[str, str] = field(default_factory=dict) # host -> первый найденный URL
    secrets: list[tuple[str, str, str]] = field(default_factory=list)  # (name, level, masked value)
    debug_libs: list[str] = field(default_factory=list)


def _mask(s: str) -> str:
    return s if len(s) <= 12 else f"{s[:6]}…{s[-4:]} ({len(s)} симв.)"


def _scan_text(text: str, scan: CodeScan, seen_secrets: set[str]) -> None:
    if "://" in text:
        for m in URL_RE.finditer(text):
            host = m.group(2).lower().rstrip(".")
            if "." not in host and not host.startswith("localhost"):
                continue
            scan.urls.setdefault(host, set()).add(m.group(1).lower())
            scan.url_samples.setdefault(host, m.group(0)[:200])
    for name, level, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            v = m.group(0)
            if v not in seen_secrets:
                seen_secrets.add(v)
                scan.secrets.append((name, level, _mask(v)))


TEXT_ASSET_EXT = (".json", ".properties", ".xml", ".txt", ".conf", ".cfg", ".yaml", ".yml", ".js", ".html", ".pem", ".key")


def scan_code(zf: zipfile.ZipFile, extra_strings: list[str] | None = None) -> CodeScan:
    scan = CodeScan()
    seen: set[str] = set()
    descriptors_hit: set[str] = set()
    for name in zf.namelist():
        if name.endswith(".dex") and "/" not in name:
            scan.dex_count += 1
            for s in dex_strings(zf.read(name)):
                scan.string_count += 1
                if s.startswith("L"):
                    for lib, prefix in DEBUG_LIBS.items():
                        if lib not in descriptors_hit and s.startswith(prefix):
                            descriptors_hit.add(lib)
                    continue
                _scan_text(s, scan, seen)
        elif name.startswith("assets/") and name.lower().endswith(TEXT_ASSET_EXT):
            zi = zf.getinfo(name)
            if zi.file_size <= 2_000_000:
                _scan_text(zf.read(name).decode("utf-8", errors="ignore"), scan, seen)
    for s in extra_strings or []:
        _scan_text(s, scan, seen)
    scan.debug_libs = sorted(descriptors_hit)
    return scan


def host_matches(host: str, patterns: list[str]) -> bool:
    return any(p.lower() in host for p in patterns if p)


def split_url(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme, parts.netloc
