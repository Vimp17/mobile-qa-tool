"""Схемы подписи APK (v1/v2/v3) и сертификаты подписанта."""
from __future__ import annotations

import hashlib
import struct
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
SIG_V2_ID = 0x7109871A
SIG_V3_ID = 0xF05368C0
SIG_V31_ID = 0x1B93AD61

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    sha256: str
    is_debug: bool
    days_left: int | None


@dataclass
class SigningInfo:
    v1: bool = False
    v2: bool = False
    v3: bool = False
    v31: bool = False
    certs: list[CertInfo] = field(default_factory=list)
    error: str = ""

    @property
    def schemes(self) -> list[str]:
        return [n for n, f in (("v1", self.v1), ("v2", self.v2), ("v3", self.v3), ("v3.1", self.v31)) if f]

    @property
    def signed(self) -> bool:
        return bool(self.schemes)


def _find_eocd(data: bytes) -> int:
    idx = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if idx < 0:
        raise ValueError("не найден конец ZIP (EOCD)")
    return idx


def read_signing_block(data: bytes) -> dict[int, bytes]:
    """Возвращает {id: value} из APK Signing Block или {} если блока нет."""
    eocd = _find_eocd(data)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_offset < 32 or data[cd_offset - 16:cd_offset] != APK_SIG_BLOCK_MAGIC:
        return {}
    block_size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    block_start = cd_offset - block_size - 8
    if block_start < 0:
        return {}
    p = block_start + 8
    end = cd_offset - 24
    out: dict[int, bytes] = {}
    while p + 12 <= end:
        ln = struct.unpack_from("<Q", data, p)[0]
        pid = struct.unpack_from("<I", data, p + 8)[0]
        out[pid] = data[p + 12:p + 8 + ln]
        p += 8 + ln
    return out


def _lp_seq(buf: bytes) -> list[bytes]:
    """Последовательность элементов с префиксом длины uint32."""
    items, p = [], 0
    while p + 4 <= len(buf):
        n = struct.unpack_from("<I", buf, p)[0]
        items.append(buf[p + 4:p + 4 + n])
        p += 4 + n
    return items


def _certs_from_v2v3(value: bytes) -> list[bytes]:
    certs: list[bytes] = []
    for signer_seq in _lp_seq(value):
        for signer in _lp_seq(signer_seq):
            if len(signer) < 4:
                continue
            signed_data = _lp_seq(signer)[0]
            parts = _lp_seq(signed_data)
            if len(parts) >= 2:
                certs.extend(_lp_seq(parts[1]))
    return certs


def _cert_info(der: bytes) -> CertInfo | None:
    if not HAVE_CRYPTO:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    not_after = cert.not_valid_after_utc
    subject = cert.subject.rfc4514_string()
    return CertInfo(
        subject=subject,
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc.date().isoformat(),
        not_after=not_after.date().isoformat(),
        sha256=hashlib.sha256(der).hexdigest().upper(),
        is_debug="CN=Android Debug" in subject,
        days_left=(not_after - datetime.now(timezone.utc)).days,
    )


def analyze_signing(path: str, zf: zipfile.ZipFile) -> SigningInfo:
    info = SigningInfo()
    der_certs: list[bytes] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
        block = read_signing_block(data)
        info.v2 = SIG_V2_ID in block
        info.v3 = SIG_V3_ID in block
        info.v31 = SIG_V31_ID in block
        for sid in (SIG_V3_ID, SIG_V2_ID):
            if sid in block and not der_certs:
                der_certs = _certs_from_v2v3(block[sid])
    except Exception as e:  # noqa: BLE001 - отчёт не должен падать из-за подписи
        info.error = f"не удалось разобрать APK Signing Block: {e}"

    sig_files = [n for n in zf.namelist()
                 if n.upper().startswith("META-INF/") and n.upper().rsplit(".", 1)[-1] in ("RSA", "DSA", "EC")
                 and n.count("/") == 1]
    info.v1 = bool(sig_files) and any(n.upper() == "META-INF/MANIFEST.MF" for n in zf.namelist())
    if not der_certs and sig_files and HAVE_CRYPTO:
        try:
            for c in pkcs7.load_der_pkcs7_certificates(zf.read(sig_files[0])):
                from cryptography.hazmat.primitives.serialization import Encoding
                der_certs.append(c.public_bytes(Encoding.DER))
        except Exception as e:  # noqa: BLE001
            info.error = info.error or f"не удалось прочитать v1-подпись: {e}"

    seen = set()
    for der in der_certs:
        ci = _cert_info(der)
        if ci and ci.sha256 not in seen:
            seen.add(ci.sha256)
            info.certs.append(ci)
    return info
