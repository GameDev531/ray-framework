#!/usr/bin/env python3
"""
ray_metadata.py — dependency-free document-metadata extractor for ray-quarry.

The FOCA method without FOCA: pull the author names, software versions, internal
file paths, and device data that published PDFs, Office documents, and images
leak — using the Python standard library alone (no PyPDF, no python-docx, no
Pillow, no exiftool). It runs in a bare environment.

Supported:
  - PDF        : the /Info dictionary (Author/Creator/Producer/Title/dates) and
                 the XMP packet (dc:creator, xmp:CreatorTool, pdf:Producer, ...).
                 Heuristic byte-scan extractor, not a full PDF parser — robust for
                 the metadata fields real documents carry, which is the point.
  - OOXML      : .docx/.xlsx/.pptx — docProps/core.xml (dc:creator,
                 cp:lastModifiedBy, revision) and docProps/app.xml (Application,
                 AppVersion, Company, Template, Manager).
  - JPEG/TIFF  : the EXIF IFD (Make, Model, Software, Artist, DateTime,
                 Copyright) and the GPS IFD (decimal lat/long) when present.

Every extracted string is also run through a leak harvester (UNC/Windows paths,
POSIX home paths, emails, internal hostnames) so a path buried in a template
field is surfaced explicitly.

Legacy OLE formats (.doc/.xls/.ppt) are not parsed — report and skip.

Usage:
  python3 ray_metadata.py <file-or-dir> [--json] [--recurse]

Exit codes: 0 = ran (even if a file had no metadata); 2 = bad invocation.
"""

import argparse
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile

# --------------------------------------------------------------------------- #
# Leak harvester — run over every extracted string value.
# --------------------------------------------------------------------------- #

_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._-]+(?:\\[^\\\s\"'<>|]+)+")
_WINPATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+")
_POSIXHOME_RE = re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s\"'<>|]*)?")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:local|internal|intranet|corp|lan|home|test|dev)\b"
)


def harvest_leaks(values):
    """Return {category: sorted-unique-matches} across all string values."""
    joined = "\n".join(v for v in values if isinstance(v, str) and v)
    out = {}
    for name, rx in (
        ("unc_paths", _UNC_RE),
        ("windows_paths", _WINPATH_RE),
        ("posix_home_paths", _POSIXHOME_RE),
        ("emails", _EMAIL_RE),
        ("internal_hosts", _HOST_RE),
    ):
        hits = sorted({m.group(0) for m in rx.finditer(joined)})
        if hits:
            out[name] = hits
    return out


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #

_PDF_INFO_KEYS = (
    "Author", "Creator", "Producer", "Title", "Subject",
    "Keywords", "Company", "CreationDate", "ModDate",
)


def _decode_pdf_string(raw):
    """Decode a PDF literal (...) or hex <...> string token (bytes) to str."""
    if raw is None:
        return None
    if raw[:1] == b"<":
        hexdigits = re.sub(rb"[^0-9A-Fa-f]", b"", raw[1:-1])
        if len(hexdigits) % 2:
            hexdigits += b"0"
        try:
            data = bytes.fromhex(hexdigits.decode("ascii"))
        except ValueError:
            return None
    else:
        body = raw[1:-1]
        # Resolve PDF escape sequences.
        out = bytearray()
        i = 0
        while i < len(body):
            c = body[i]
            if c == 0x5C and i + 1 < len(body):  # backslash
                nxt = body[i + 1]
                simple = {0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09,
                          0x62: 0x08, 0x66: 0x0C, 0x28: 0x28,
                          0x29: 0x29, 0x5C: 0x5C}
                if nxt in simple:
                    out.append(simple[nxt]); i += 2; continue
                if 0x30 <= nxt <= 0x37:  # octal, up to 3 digits
                    j = i + 1; digits = b""
                    while j < len(body) and len(digits) < 3 and 0x30 <= body[j] <= 0x37:
                        digits += body[j:j + 1]; j += 1
                    out.append(int(digits, 8) & 0xFF); i = j; continue
                out.append(nxt); i += 2; continue
            out.append(c); i += 1
        data = bytes(out)
    # UTF-16 BOM?
    if data[:2] in (b"\xfe\xff", b"\xff\xfe"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("latin-1").strip()
    except UnicodeDecodeError:
        return None


def _pdf_info_dict(data):
    """Heuristic extraction of /Info-style keys from raw PDF bytes."""
    info = {}
    for key in _PDF_INFO_KEYS:
        # /Key (literal) or /Key <hex>
        rx = re.compile(rb"/" + key.encode("ascii") +
                        rb"\s*(\((?:[^()\\]|\\.|\([^)]*\))*\)|<[0-9A-Fa-f\s]*>)")
        m = rx.search(data)
        if m:
            val = _decode_pdf_string(m.group(1))
            if val:
                info[key] = val
    return info


def _pdf_xmp(data):
    """Parse an embedded XMP packet, if any, into a flat dict."""
    start = data.find(b"<x:xmpmeta")
    if start == -1:
        start = data.find(b"<?xpacket begin")
    if start == -1:
        return {}
    end = data.find(b"</x:xmpmeta>")
    if end != -1:
        end += len(b"</x:xmpmeta>")
    else:
        end = data.find(b"<?xpacket end")
        if end == -1:
            return {}
    chunk = data[start:end]
    # Trim to the xmpmeta element for the XML parser.
    xm = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", chunk, re.DOTALL)
    if not xm:
        return {}
    out = {}
    try:
        root = ET.fromstring(xm.group(0))
    except ET.ParseError:
        return {}
    wanted = {
        "creator": "dc:creator", "CreatorTool": "xmp:CreatorTool",
        "Producer": "pdf:Producer", "CreateDate": "xmp:CreateDate",
        "ModifyDate": "xmp:ModifyDate", "title": "dc:title",
        "description": "dc:description",
    }
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        for local, label in wanted.items():
            if tag == local:
                # dc:creator etc. often wrap values in rdf:Seq/li children.
                texts = [t.strip() for t in el.itertext() if t and t.strip()]
                if texts:
                    out[label] = "; ".join(dict.fromkeys(texts))
        for attr, aval in el.attrib.items():
            a = attr.split("}")[-1]
            if a in ("CreatorTool", "Producer", "CreateDate", "ModifyDate") and aval.strip():
                out.setdefault("xmp:" + a, aval.strip())
    return out


def extract_pdf(path):
    with open(path, "rb") as fh:
        data = fh.read()
    meta = {}
    info = _pdf_info_dict(data)
    if info:
        meta["info"] = info
    xmp = _pdf_xmp(data)
    if xmp:
        meta["xmp"] = xmp
    return meta


# --------------------------------------------------------------------------- #
# OOXML (docx/xlsx/pptx)
# --------------------------------------------------------------------------- #

_OOXML_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


def _text_of(root, path):
    el = root.find(path, _OOXML_NS)
    return el.text.strip() if el is not None and el.text and el.text.strip() else None


def extract_ooxml(path):
    meta = {}
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {}
    with zf:
        names = set(zf.namelist())
        if "docProps/core.xml" in names:
            try:
                root = ET.fromstring(zf.read("docProps/core.xml"))
                core = {}
                for label, xp in (
                    ("creator", "dc:creator"),
                    ("lastModifiedBy", "cp:lastModifiedBy"),
                    ("revision", "cp:revision"),
                    ("created", "dcterms:created"),
                    ("modified", "dcterms:modified"),
                    ("title", "dc:title"),
                    ("subject", "dc:subject"),
                    ("keywords", "cp:keywords"),
                    ("category", "cp:category"),
                    ("lastPrinted", "cp:lastPrinted"),
                ):
                    v = _text_of(root, xp)
                    if v:
                        core[label] = v
                if core:
                    meta["core"] = core
            except ET.ParseError:
                pass
        if "docProps/app.xml" in names:
            try:
                root = ET.fromstring(zf.read("docProps/app.xml"))
                app = {}
                for label, xp in (
                    ("Application", "ep:Application"),
                    ("AppVersion", "ep:AppVersion"),
                    ("Company", "ep:Company"),
                    ("Manager", "ep:Manager"),
                    ("Template", "ep:Template"),
                    ("TotalTime", "ep:TotalTime"),
                ):
                    v = _text_of(root, xp)
                    if v:
                        app[label] = v
                if app:
                    meta["app"] = app
            except ET.ParseError:
                pass
    return meta


# --------------------------------------------------------------------------- #
# EXIF (JPEG / TIFF)
# --------------------------------------------------------------------------- #

_EXIF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
    0x013B: "Artist", 0x0132: "DateTime", 0x8298: "Copyright",
    0x9003: "DateTimeOriginal", 0x8769: "_ExifIFD", 0x8825: "_GPSIFD",
    0x9286: "UserComment", 0xA430: "OwnerName", 0xA433: "LensMake",
    0xA434: "LensModel",
}
_GPS_TAGS = {
    0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
    0x0006: "GPSAltitude",
}
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _read_tiff_ifd(buf, base, offset, endian, tagmap):
    """Parse one IFD; return ({name: value}, next_ifd_offset, {name: raw_offset})."""
    out, raw_ptrs = {}, {}
    if offset + 2 > len(buf):
        return out, 0, raw_ptrs
    (count,) = struct.unpack(endian + "H", buf[offset:offset + 2])
    p = offset + 2
    for _ in range(count):
        if p + 12 > len(buf):
            break
        tag, typ, num = struct.unpack(endian + "HHI", buf[p:p + 8])
        size = _TYPE_SIZES.get(typ, 0) * num
        if size == 0:
            p += 12
            continue
        if size <= 4:
            valbytes = buf[p + 8:p + 8 + size]
        else:
            (voff,) = struct.unpack(endian + "I", buf[p + 8:p + 12])
            valbytes = buf[base + voff:base + voff + size]
        name = tagmap.get(tag)
        if name:
            raw_ptrs[name] = valbytes
            out[name] = _decode_exif_value(typ, num, valbytes, endian)
        p += 12
    nxt = 0
    if p + 4 <= len(buf):
        (nxt,) = struct.unpack(endian + "I", buf[p:p + 4])
    return out, nxt, raw_ptrs


def _decode_exif_value(typ, num, valbytes, endian):
    if typ == 2:  # ASCII
        return valbytes.split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
    if typ in (3, 4, 1):  # SHORT/LONG/BYTE
        fmt = {1: "B", 3: "H", 4: "I"}[typ]
        vals = struct.unpack(endian + fmt * num, valbytes[:_TYPE_SIZES[typ] * num])
        return vals[0] if num == 1 else list(vals)
    if typ == 5:  # RATIONAL
        vals = []
        for i in range(num):
            n, d = struct.unpack(endian + "II", valbytes[i * 8:i * 8 + 8])
            vals.append((n, d))
        return vals[0] if num == 1 else vals
    return valbytes.hex()


def _gps_to_decimal(rationals, ref):
    try:
        deg = rationals[0][0] / rationals[0][1]
        minute = rationals[1][0] / rationals[1][1]
        sec = rationals[2][0] / rationals[2][1]
    except (IndexError, ZeroDivisionError, TypeError):
        return None
    dec = deg + minute / 60 + sec / 3600
    if ref in ("S", "W"):
        dec = -dec
    return round(dec, 6)


def _parse_tiff(tiff, base_in_file=0):
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return {}
    (ifd0_off,) = struct.unpack(endian + "I", tiff[4:8])
    meta, _, _ = _read_tiff_ifd(tiff, 0, ifd0_off, endian, _EXIF_TAGS)
    result = {k: v for k, v in meta.items() if not k.startswith("_")}
    # Exif sub-IFD (Software sometimes lives here).
    if "_ExifIFD" in meta and isinstance(meta["_ExifIFD"], int):
        sub, _, _ = _read_tiff_ifd(tiff, 0, meta["_ExifIFD"], endian, _EXIF_TAGS)
        for k, v in sub.items():
            if not k.startswith("_"):
                result.setdefault(k, v)
    # GPS IFD.
    if "_GPSIFD" in meta and isinstance(meta["_GPSIFD"], int):
        gps, _, _ = _read_tiff_ifd(tiff, 0, meta["_GPSIFD"], endian, _GPS_TAGS)
        lat = _gps_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
        lon = _gps_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
        if lat is not None and lon is not None:
            result["GPSPosition"] = "{}, {}".format(lat, lon)
    return result


def extract_image(path):
    with open(path, "rb") as fh:
        data = fh.read(2_000_000)  # metadata lives at the head
    if data[:2] == b"\xff\xd8":  # JPEG — find APP1/Exif
        idx = data.find(b"Exif\x00\x00")
        if idx == -1:
            return {}
        tiff = data[idx + 6:]
        meta = _parse_tiff(tiff)
        return {"exif": meta} if meta else {}
    if data[:2] in (b"II", b"MM"):  # TIFF
        meta = _parse_tiff(data)
        return {"exif": meta} if meta else {}
    return {}


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def _collect_strings(meta):
    """Flatten all string leaf values from a nested metadata dict."""
    out = []

    def walk(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)

    walk(meta)
    return out


def extract_one(path):
    ext = os.path.splitext(path)[1].lower()
    record = {"file": path, "type": ext.lstrip(".") or "unknown"}
    try:
        if ext == ".pdf":
            meta = extract_pdf(path)
        elif ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
            meta = extract_ooxml(path)
        elif ext in (".jpg", ".jpeg", ".tif", ".tiff"):
            meta = extract_image(path)
        elif ext in (".doc", ".xls", ".ppt"):
            record["skipped"] = "legacy OLE format not supported (OOXML only)"
            return record
        else:
            record["skipped"] = "unsupported extension"
            return record
    except (OSError, struct.error, ValueError) as exc:
        record["error"] = "{}: {}".format(type(exc).__name__, exc)
        return record

    record["metadata"] = meta
    if meta:
        leaks = harvest_leaks(_collect_strings(meta))
        if leaks:
            record["leaks"] = leaks
    else:
        record["metadata"] = {}
        record["note"] = "no extractable metadata"
    return record


def iter_files(target, recurse):
    if os.path.isfile(target):
        yield target
        return
    if os.path.isdir(target):
        if recurse:
            for root, _, files in os.walk(target):
                for f in sorted(files):
                    yield os.path.join(root, f)
        else:
            for f in sorted(os.listdir(target)):
                p = os.path.join(target, f)
                if os.path.isfile(p):
                    yield p


def _print_human(rec):
    print("=== {} [{}]".format(rec["file"], rec.get("type", "?")))
    if rec.get("skipped"):
        print("    skipped: {}".format(rec["skipped"]))
        return
    if rec.get("error"):
        print("    error: {}".format(rec["error"]))
        return
    meta = rec.get("metadata") or {}
    if not meta:
        print("    (no extractable metadata)")
    for section, fields in meta.items():
        print("    [{}]".format(section))
        for k, v in fields.items():
            print("        {}: {}".format(k, v))
    if rec.get("leaks"):
        print("    [leaks]")
        for cat, hits in rec["leaks"].items():
            for h in hits:
                print("        {}: {}".format(cat, h))


def main(argv):
    ap = argparse.ArgumentParser(description="Dependency-free document metadata extractor (ray-quarry).")
    ap.add_argument("target", help="a file or a directory of documents")
    ap.add_argument("--json", action="store_true", help="emit a JSON array of records")
    ap.add_argument("--recurse", action="store_true", help="recurse into subdirectories")
    args = ap.parse_args(argv)

    if not os.path.exists(args.target):
        sys.stderr.write("error: no such path: {}\n".format(args.target))
        return 2

    records = [extract_one(p) for p in iter_files(args.target, args.recurse)]

    if args.json:
        json.dump(records, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        for rec in records:
            _print_human(rec)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
