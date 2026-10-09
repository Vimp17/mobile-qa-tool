"""Нативные библиотеки: ABI и совместимость с 16 KB page size (требование Google Play)."""
from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field

PAGE_16K = 16384
PT_LOAD = 1
ABI_64 = {"arm64-v8a", "x86_64"}


@dataclass
class NativeLib:
    path: str
    abi: str
    min_load_align: int | None   # минимальное p_align среди PT_LOAD
    stored: bool                 # без сжатия (extractNativeLibs=false)
    zip_aligned_16k: bool | None # смещение данных в ZIP кратно 16 KB

    @property
    def elf_16k_ok(self) -> bool | None:
        return None if self.min_load_align is None else self.min_load_align >= PAGE_16K


@dataclass
class NativeInfo:
    abis: list[str] = field(default_factory=list)
    libs: list[NativeLib] = field(default_factory=list)

    @property
    def has_native(self) -> bool:
        return bool(self.libs)

    def not_16k(self) -> list[NativeLib]:
        out = []
        for lib in self.libs:
            if lib.abi not in ABI_64:
                continue
            if lib.elf_16k_ok is False or (lib.stored and lib.zip_aligned_16k is False):
                out.append(lib)
        return out


def elf_min_load_align(data: bytes) -> int | None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    try:
        if is64:
            phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", data, 0x36)
        else:
            phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", data, 0x2A)
        aligns = []
        for i in range(phnum):
            p = phoff + i * phentsize
            ptype = struct.unpack_from(endian + "I", data, p)[0]
            if ptype != PT_LOAD:
                continue
            if is64:
                align = struct.unpack_from(endian + "Q", data, p + 0x30)[0]
            else:
                align = struct.unpack_from(endian + "I", data, p + 0x1C)[0]
            aligns.append(align)
        return min(aligns) if aligns else None
    except struct.error:
        return None


def _data_offset(fp, info: zipfile.ZipInfo) -> int:
    fp.seek(info.header_offset)
    hdr = fp.read(30)
    name_len, extra_len = struct.unpack_from("<HH", hdr, 26)
    return info.header_offset + 30 + name_len + extra_len


def analyze_native(apk_path: str, zf: zipfile.ZipFile) -> NativeInfo:
    info = NativeInfo()
    abis: set[str] = set()
    with open(apk_path, "rb") as fp:
        for zi in zf.infolist():
            n = zi.filename
            if not (n.startswith("lib/") and n.endswith(".so")) or n.count("/") != 2:
                continue
            abi = n.split("/")[1]
            abis.add(abi)
            # Для проверки выравнивания хватает заголовков; читаем первые 64 КБ
            with zf.open(zi) as f:
                head = f.read(65536)
            stored = zi.compress_type == zipfile.ZIP_STORED
            aligned = (_data_offset(fp, zi) % PAGE_16K == 0) if stored else None
            info.libs.append(NativeLib(n, abi, elf_min_load_align(head), stored, aligned))
    info.abis = sorted(abis)
    return info
