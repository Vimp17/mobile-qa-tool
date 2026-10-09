"""Минимальный парсер resources.arsc.

Нужен для двух вещей: разрешить ссылки вида @string/app_name (label, versionName)
и получить список локалей, для которых в сборке есть строки.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from .axml import TYPE_REFERENCE, TYPE_STRING, format_value, parse_string_pool

RES_TABLE_TYPE = 0x0002
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02
ENTRY_FLAG_COMPLEX = 0x0001
ENTRY_FLAG_COMPACT = 0x0008
NO_ENTRY = 0xFFFFFFFF


def _decode_locale_part(b: bytes, base: str) -> str:
    if not b or b == b"\x00\x00":
        return ""
    if b[0] & 0x80:  # упакованный 3-буквенный код
        first, second = b[0], b[1]
        chars = [second & 0x1F, ((second & 0xE0) >> 5) | ((first & 0x03) << 3), (first & 0x7C) >> 2]
        return "".join(chr(c + ord(base)) for c in chars)
    return b.decode("ascii", errors="ignore").rstrip("\x00")


@dataclass
class ResourceTable:
    strings: list[str] = field(default_factory=list)
    # res_id -> list[(locale, value)]
    values: dict[int, list[tuple[str, Any]]] = field(default_factory=dict)
    type_names: dict[tuple[int, int], str] = field(default_factory=dict)  # (pkg, type) -> "string"
    locales_by_type: dict[str, set[str]] = field(default_factory=dict)
    package_name: str = ""

    def resolve(self, value: Any, depth: int = 0) -> Any:
        """Разрешает ResRef в значение по умолчанию (конфигурация без локали в приоритете)."""
        res_id = getattr(value, "res_id", None)
        if res_id is None or depth > 5:
            return value
        candidates = self.values.get(res_id)
        if not candidates:
            return value
        chosen = next((v for loc, v in candidates if loc == ""), candidates[0][1])
        return self.resolve(chosen, depth + 1)

    @property
    def string_locales(self) -> list[str]:
        return sorted(self.locales_by_type.get("string", set()) - {""})


def parse_arsc(data: bytes) -> ResourceTable:
    table = ResourceTable()
    ctype, hsize, _size = struct.unpack_from("<HHI", data, 0)
    if ctype != RES_TABLE_TYPE:
        raise ValueError("не resources.arsc")
    off = hsize
    while off + 8 <= len(data):
        ctype, chsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == RES_STRING_POOL_TYPE:
            table.strings = parse_string_pool(data, off)
        elif ctype == RES_TABLE_PACKAGE_TYPE:
            _parse_package(data, off, chsize, csize, table)
        off += csize
    return table


def _parse_package(data: bytes, start: int, hsize: int, size: int, table: ResourceTable) -> None:
    pkg_id = struct.unpack_from("<I", data, start + 8)[0]
    name = data[start + 12:start + 12 + 256].decode("utf-16-le", errors="ignore").split("\x00")[0]
    if not table.package_name:
        table.package_name = name
    type_strings_off = struct.unpack_from("<I", data, start + 268)[0]
    type_names: list[str] = []
    if type_strings_off:
        type_names = parse_string_pool(data, start + type_strings_off)

    off = start + hsize
    end = start + size
    while off + 8 <= end:
        ctype, chsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == RES_TABLE_TYPE_TYPE:
            _parse_type(data, off, chsize, csize, pkg_id, type_names, table)
        off += csize


def _parse_type(data, start, hsize, size, pkg_id, type_names, table: ResourceTable) -> None:
    type_id, flags, _res, entry_count, entries_start = struct.unpack_from("<BBHII", data, start + 8)
    cfg_off = start + 20
    cfg_size = struct.unpack_from("<I", data, cfg_off)[0]
    lang = _decode_locale_part(data[cfg_off + 8:cfg_off + 10], "a") if cfg_size >= 12 else ""
    country = _decode_locale_part(data[cfg_off + 10:cfg_off + 12], "0") if cfg_size >= 12 else ""
    locale = lang + (f"-r{country}" if country else "")
    tname = type_names[type_id - 1] if 0 < type_id <= len(type_names) else f"type{type_id}"
    table.type_names[(pkg_id, type_id)] = tname
    table.locales_by_type.setdefault(tname, set()).add(lang)

    # Значения нужны только для строк и простых типов — этого хватает для label/versionName.
    if tname not in ("string", "bool", "integer", "xml"):
        return

    idx_off = start + hsize
    pairs: list[tuple[int, int]] = []
    if flags & FLAG_SPARSE:
        for i in range(entry_count):
            idx, o16 = struct.unpack_from("<HH", data, idx_off + i * 4)
            pairs.append((idx, o16 * 4))
    elif flags & FLAG_OFFSET16:
        for i in range(entry_count):
            o16 = struct.unpack_from("<H", data, idx_off + i * 2)[0]
            if o16 != 0xFFFF:
                pairs.append((i, o16 * 4))
    else:
        for i in range(entry_count):
            o = struct.unpack_from("<I", data, idx_off + i * 4)[0]
            if o != NO_ENTRY:
                pairs.append((i, o))

    base = start + entries_start
    for idx, o in pairs:
        p = base + o
        try:
            esize, eflags = struct.unpack_from("<HH", data, p)
            if eflags & ENTRY_FLAG_COMPACT:
                dtype = eflags >> 8
                dval = struct.unpack_from("<I", data, p + 4)[0]
            elif eflags & ENTRY_FLAG_COMPLEX:
                continue
            else:
                _vsize, _r0, dtype, dval = struct.unpack_from("<HBBI", data, p + esize)
        except struct.error:
            continue
        if dtype == TYPE_STRING:
            value = table.strings[dval] if dval < len(table.strings) else ""
        elif dtype == TYPE_REFERENCE:
            value = format_value(dtype, dval, None, [])
        else:
            value = format_value(dtype, dval, None, table.strings)
        res_id = (pkg_id << 24) | (type_id << 16) | idx
        table.values.setdefault(res_id, []).append((locale, value))
