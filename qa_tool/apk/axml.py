"""Парсер бинарного Android XML (AndroidManifest.xml и res/xml/* внутри APK).

Без внешних зависимостей. Возвращает простое дерево XmlElement.
Формат: frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Iterator

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

UTF8_FLAG = 1 << 8

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_FIRST_COLOR = 0x1C
TYPE_LAST_COLOR = 0x1F

# android.R.attr — на случай, если имена атрибутов в пуле строк обфусцированы.
ANDROID_ATTR_IDS = {
    0x01010001: "label", 0x01010002: "icon", 0x01010003: "name",
    0x01010006: "permission", 0x01010007: "readPermission", 0x01010008: "writePermission",
    0x01010009: "protectionLevel", 0x0101000E: "enabled", 0x0101000F: "debuggable",
    0x01010010: "exported", 0x01010018: "authorities", 0x0101001B: "grantUriPermissions",
    0x01010027: "scheme", 0x01010028: "host", 0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode", 0x0101021C: "versionName", 0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion", 0x01010272: "testOnly", 0x01010280: "allowBackup",
    0x0101028E: "required", 0x010104EA: "extractNativeLibs", 0x010104EB: "fullBackupContent",
    0x010104EC: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
    0x01010572: "compileSdkVersion", 0x01010573: "compileSdkVersionCodename",
}


@dataclass(frozen=True)
class ResRef:
    """Ссылка на ресурс (@0x7f...)."""

    res_id: int

    def __str__(self) -> str:
        return f"@0x{self.res_id:08x}"


@dataclass
class XmlElement:
    tag: str
    attrs: dict[str, Any] = field(default_factory=dict)
    children: list["XmlElement"] = field(default_factory=list)
    text: str = ""

    def get(self, name: str, default: Any = None) -> Any:
        return self.attrs.get(name, default)

    def iter(self, tag: str | None = None) -> Iterator["XmlElement"]:
        if tag is None or self.tag == tag:
            yield self
        for c in self.children:
            yield from c.iter(tag)

    def find_all(self, tag: str) -> list["XmlElement"]:
        return [c for c in self.children if c.tag == tag]

    def find(self, tag: str) -> "XmlElement | None":
        for c in self.children:
            if c.tag == tag:
                return c
        return None


class AxmlError(ValueError):
    pass


def _decode_length(data: bytes, off: int, utf8: bool) -> tuple[int, int]:
    if utf8:
        n = data[off]
        off += 1
        if n & 0x80:
            n = ((n & 0x7F) << 8) | data[off]
            off += 1
        return n, off
    n = struct.unpack_from("<H", data, off)[0]
    off += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, off)[0]
        off += 2
    return n, off


def parse_string_pool(data: bytes, start: int) -> list[str]:
    """Разбирает ResStringPool, начинающийся с offset start (на заголовке чанка)."""
    (_type, header_size, _size, count, _style_count, flags,
     strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, start)
    utf8 = bool(flags & UTF8_FLAG)
    offsets = struct.unpack_from(f"<{count}I", data, start + header_size)
    base = start + strings_start
    out: list[str] = []
    for o in offsets:
        p = base + o
        try:
            if utf8:
                _u16len, p = _decode_length(data, p, True)
                blen, p = _decode_length(data, p, True)
                out.append(data[p:p + blen].decode("utf-8", errors="replace"))
            else:
                clen, p = _decode_length(data, p, False)
                out.append(data[p:p + clen * 2].decode("utf-16-le", errors="replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def format_value(data_type: int, value: int, raw_str: str | None, strings: list[str]) -> Any:
    if raw_str is not None and data_type == TYPE_STRING:
        return raw_str
    if data_type == TYPE_STRING:
        return strings[value] if 0 <= value < len(strings) else ""
    if data_type == TYPE_INT_BOOLEAN:
        return value != 0
    if data_type == TYPE_INT_DEC:
        return struct.unpack("<i", struct.pack("<I", value))[0]
    if data_type == TYPE_INT_HEX:
        return value
    if data_type in (TYPE_REFERENCE, TYPE_ATTRIBUTE):
        return ResRef(value)
    if data_type == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", value))[0]
    if TYPE_FIRST_COLOR <= data_type <= TYPE_LAST_COLOR:
        return f"#{value:08x}"
    if data_type == TYPE_NULL:
        return None
    return value


def parse_axml(data: bytes) -> XmlElement:
    if len(data) < 8:
        raise AxmlError("слишком короткий файл")
    ctype, _hsize, total = struct.unpack_from("<HHI", data, 0)
    if ctype != RES_XML_TYPE:
        raise AxmlError(f"не бинарный XML (тип 0x{ctype:04x})")
    total = min(total, len(data))

    strings: list[str] = []
    res_map: list[int] = []
    root: XmlElement | None = None
    stack: list[XmlElement] = []

    off = 8
    while off + 8 <= total:
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            break
        if ctype == RES_STRING_POOL_TYPE:
            strings = parse_string_pool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - hsize) // 4
            res_map = list(struct.unpack_from(f"<{n}I", data, off + hsize))
        elif ctype == RES_XML_START_ELEMENT:
            ext = off + hsize
            _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, ext)
            el = XmlElement(tag=strings[name_idx] if name_idx < len(strings) else "?")
            p = ext + attr_start
            for _ in range(attr_count):
                _ans, aname, araw, _vsize, _res0, dtype, dval = struct.unpack_from("<IIIHBBI", data, p)
                p += attr_size or 20
                name = strings[aname] if aname < len(strings) else ""
                if aname < len(res_map) and res_map[aname] in ANDROID_ATTR_IDS:
                    # Имя по ID надёжнее: обфускаторы (например, AndResGuard) портят пул строк.
                    name = ANDROID_ATTR_IDS[res_map[aname]]
                raw = strings[araw] if araw != 0xFFFFFFFF and araw < len(strings) else None
                el.attrs[name] = format_value(dtype, dval, raw, strings)
            if stack:
                stack[-1].children.append(el)
            else:
                root = el
            stack.append(el)
        elif ctype == RES_XML_CDATA:
            idx = struct.unpack_from("<I", data, off + hsize)[0]
            if stack and idx < len(strings):
                stack[-1].text += strings[idx].strip()
        elif ctype == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        off += csize

    if root is None:
        raise AxmlError("в XML нет корневого элемента")
    return root
