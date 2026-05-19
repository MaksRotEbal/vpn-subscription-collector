#!/usr/bin/env python3
"""Сборщик и сортировщик публичных VPN-подписок."""

from __future__ import annotations

import argparse
import base64
import socket
import shutil
import json
import re
import sys
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse, urlunparse

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMES = (
    "vless",
    "vmess",
    "trojan",
    "ss",
    "shadowsocks",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "wireguard",
)
FLAG_RE = re.compile(
    r"[\U0001F1E6-\U0001F1FF]{2}"
    r"|[\U0001F3F4][\U0001F3F4-\U0001F3FF]*[\U0001F3F4]"
)
CC_RE = re.compile(r"\b([A-Z]{2})\b")
URI_LINE_RE = re.compile(
    r"^(?:" + "|".join(SCHEMES) + r")://",
    re.IGNORECASE,
)

SUB_WL = "MaksRotEbal_WL"
SUB_BL = "MaksRotEbal_BL"
SUB_ALL = "MaksRotEbal_ALL"


@dataclass
class ParsedServer:
    uri: str
    scheme: str
    host: str
    port: int
    display_name: str
    bypass: str  # БС | ЧС
    country_code: str
    country_name: str
    flag: str

    @property
    def dedup_key(self) -> str:
        return f"{self.scheme.lower()}:{self.host.lower()}:{self.port}"

    @property
    def sort_key(self) -> tuple:
        return (self.country_name, self.bypass, self.host, self.port)

    @property
    def label(self) -> str:
        return self.country_name


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def decode_subscription_body(text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    if URI_LINE_RE.search(text.splitlines()[0]):
        return text
    try:
        raw = base64.b64decode(text, validate=True).decode("utf-8", errors="ignore")
        if URI_LINE_RE.search(raw.splitlines()[0] if raw.splitlines() else ""):
            return raw
    except Exception:
        pass
    try:
        raw = base64.urlsafe_b64decode(text + "==").decode("utf-8", errors="ignore")
        if raw and (URI_LINE_RE.search(raw) or "://" in raw):
            return raw
    except Exception:
        pass
    return text


def extract_lines(body: str) -> list[str]:
    lines: list[str] = []
    for line in body.replace("\r", "").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if URI_LINE_RE.match(line):
            lines.append(line)
    return lines


def flag_to_cc(flag: str) -> str | None:
    if len(flag) != 2:
        return None
    base = 0x1F1E6
    try:
        return "".join(chr(ord(c) - base + ord("A")) for c in flag).upper()
    except (TypeError, ValueError):
        return None


def detect_country(
    text: str,
    host: str,
    country_names: dict[str, list[str]],
    tld_country: dict[str, str],
) -> tuple[str, str, str]:
    for flag in FLAG_RE.findall(text):
        cc = flag_to_cc(flag)
        if cc and cc in country_names:
            name, emoji = country_names[cc]
            return cc, name, emoji

    for m in CC_RE.finditer(text.upper()):
        cc = m.group(1)
        if cc in country_names and cc not in ("BS", "CS"):  # не путать с типом обхода
            name, emoji = country_names[cc]
            return cc, name, emoji

    host_l = host.lower()
    for tld, cc in sorted(tld_country.items(), key=lambda x: -len(x[0])):
        if host_l.endswith("." + tld) or host_l == tld:
            if cc in country_names:
                name, emoji = country_names[cc]
                return cc, name, emoji

    unk = country_names.get("UNKNOWN", ["Unknown", ""])
    return "UNKNOWN", unk[0], unk[1] if len(unk) > 1 else ""


def classify_bypass(
    text: str,
    rules_bs: list[str],
    rules_cs: list[str],
    default: str,
) -> str:
    low = text.lower()
    for kw in rules_bs:
        if kw.lower() in low:
            return "БС"
    for kw in rules_cs:
        if kw.lower() in low:
            return "ЧС"
    return default


def parse_vmess(uri: str) -> tuple[str, int, str] | None:
    payload = uri.split("://", 1)[1].split("#", 1)[0]
    pad = "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + pad))
    except Exception:
        try:
            data = json.loads(base64.b64decode(payload + pad))
        except Exception:
            return None
    host = str(data.get("add") or data.get("host") or "")
    port = int(data.get("port") or 0)
    name = str(data.get("ps") or data.get("remarks") or "")
    if not host or not port:
        return None
    return host, port, name


def parse_standard_uri(uri: str) -> tuple[str, int, str] | None:
    try:
        parsed = urlparse(uri)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme == "ss" and "@" not in parsed.netloc:
        # ss://base64(method:pass@host:port)#name
        try:
            decoded = base64.urlsafe_b64decode(parsed.netloc + "==").decode()
            if "@" in decoded:
                hostport = decoded.split("@", 1)[1]
                host, _, port_s = hostport.rpartition(":")
                return host, int(port_s), unquote(parsed.fragment or "")
        except Exception:
            pass
    host = parsed.hostname or ""
    port = parsed.port
    if not host:
        if "@" in parsed.netloc:
            host = parsed.netloc.rsplit("@", 1)[-1].split(":")[0]
        else:
            return None
    if not port:
        port = 443 if scheme in ("trojan", "vless", "tuic") else 80
    name = unquote(parsed.fragment or "")
    qs = parse_qs(parsed.query)
    for key in ("remarks", "remark", "name"):
        if key in qs and qs[key]:
            name = name or qs[key][0]
    return host, port, name


def parse_uri(uri: str) -> tuple[str, str, int, str] | None:
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "shadowsocks":
        scheme = "ss"
    if scheme == "hy2":
        scheme = "hysteria2"
    if scheme not in {s.replace("shadowsocks", "ss") for s in SCHEMES}:
        return None
    if scheme == "vmess":
        info = parse_vmess(uri)
    else:
        info = parse_standard_uri(uri)
    if not info:
        return None
    host, port, name = info
    return scheme, host, port, name


def rename_uri(uri: str, label: str) -> str:
    scheme = uri.split("://", 1)[0].lower()
    safe_label = label

    if scheme == "vmess":
        payload = uri.split("://", 1)[1].split("#", 1)[0]
        pad = "=" * (-len(payload) % 4)
        try:
            data = json.loads(base64.urlsafe_b64decode(payload + pad))
        except Exception:
            data = json.loads(base64.b64decode(payload + pad))
        data["ps"] = safe_label
        new_payload = base64.urlsafe_b64encode(
            json.dumps(data, ensure_ascii=False).encode()
        ).decode().rstrip("=")
        return f"vmess://{new_payload}"

    try:
        parsed = urlparse(uri)
    except ValueError:
        return uri
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for key in ("remarks", "remark", "name"):
        if key in qs:
            qs[key] = [safe_label]
    flat_qs = []
    for k, vals in qs.items():
        for v in vals:
            flat_qs.append(f"{k}={quote(v, safe='')}" if v else k)
    query = "&".join(flat_qs) if flat_qs else parsed.query
    # фрагмент — основное отображаемое имя в большинстве клиентов
    new = parsed._replace(query=query, fragment=quote(safe_label, safe=" "))
    return urlunparse(new)


def process_uri(
    uri: str,
    rules_bs: list[str],
    rules_cs: list[str],
    default_bypass: str,
    country_names: dict[str, list[str]],
    tld_country: dict[str, str],
) -> ParsedServer | None:
    parsed = parse_uri(uri)
    if not parsed:
        return None
    scheme, host, port, name = parsed
    meta = f"{name} {host} {uri}"
    bypass = classify_bypass(meta, rules_bs, rules_cs, default_bypass)
    cc, cname, flag = detect_country(meta, host, country_names, tld_country)
    label = cname
    final_uri = rename_uri(uri, label)
    return ParsedServer(
        uri=final_uri,
        scheme=scheme,
        host=host,
        port=port,
        display_name=label,
        bypass=bypass,
        country_code=cc,
        country_name=cname,
        flag=flag,
    )



def tcp_reachable(host: str, port: int, timeout: float) -> bool:
    if not host or len(host) > 253:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, UnicodeError):
        return False


def filter_alive(
    servers: list[ParsedServer],
    timeout: float,
    workers: int,
) -> list[ParsedServer]:
    if not servers:
        return []
    alive: list[ParsedServer] = []
    workers = max(1, min(workers, 50))

    def check(s: ParsedServer) -> tuple[ParsedServer, bool]:
        return s, tcp_reachable(s.host, s.port, timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check, s) for s in servers]
        for fut in as_completed(futures):
            srv, ok = fut.result()
            if ok:
                alive.append(srv)
    alive.sort(key=lambda s: s.sort_key)
    return alive


def clear_output_dir(out_dir: Path) -> None:
    if not out_dir.exists():
        out_dir.mkdir(parents=True, exist_ok=True)
        return
    for child in out_dir.iterdir():
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)

def fetch_source(url: str, timeout: int, user_agent: str) -> str:
    resp = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": user_agent},
    )
    resp.raise_for_status()
    return resp.text


def write_subscription(path: Path, uris: list[str]) -> None:
    """Subscription file: single base64 of newline-joined plain URI lines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(uris)
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    path.write_text(encoded, encoding="utf-8")
    plain_path = path.parent / f"{path.stem}.plain.txt"
    plain_path.write_text((body + "\n") if body else "", encoding="utf-8")



def collect(
    sources_path: Path,
    classification_path: Path,
    offline_samples: list[str] | None = None,
    skip_health_check: bool = False,
) -> dict[str, Any]:
    src_cfg = load_yaml(sources_path)
    cls_cfg = load_yaml(classification_path)
    settings = src_cfg.get("settings") or {}
    out_dir = ROOT / settings.get("output_dir", "output")
    timeout = int(settings.get("request_timeout_sec", 30))
    user_agent = settings.get("user_agent", "vpn-sub-collector/1.0")

    country_names = {
        str(k).upper(): v for k, v in (cls_cfg.get("country_names") or {}).items()
    }
    tld_country = {
        str(k).lower(): str(v).upper()
        for k, v in (cls_cfg.get("tld_country") or {}).items()
    }
    rules_bs = cls_cfg.get("bypass_bs") or []
    rules_cs = cls_cfg.get("bypass_cs") or []
    default_bypass = cls_cfg.get("default_bypass", "ЧС")

    all_lines: list[str] = []
    if offline_samples:
        all_lines.extend(offline_samples)
    else:
        for src in src_cfg.get("sources") or []:
            if not src.get("enabled"):
                continue
            url = src.get("url")
            if not url:
                continue
            print(f"Fetching {src.get('name', url)}...")
            try:
                body = fetch_source(url, timeout, user_agent)
            except requests.RequestException as exc:
                print(f"  skip {src.get('name')}: {exc}", file=sys.stderr)
                continue
            decoded = decode_subscription_body(body)
            all_lines.extend(extract_lines(decoded))

    deduped: dict[str, ParsedServer] = {}
    skipped = 0
    for line in all_lines:
        try:
            srv = process_uri(
                line, rules_bs, rules_cs, default_bypass, country_names, tld_country
            )
        except (ValueError, json.JSONDecodeError, KeyError):
            skipped += 1
            continue
        if srv:
            deduped.setdefault(srv.dedup_key, srv)
    servers = sorted(deduped.values(), key=lambda s: s.sort_key)

    connect_timeout = float(settings.get("connect_timeout_sec", 4))
    health_workers = int(settings.get("health_workers", 50))
    max_wl = int(settings.get("max_wl", 100))
    max_bl = int(settings.get("max_bl", 100))
    max_all = int(settings.get("max_all", 200))
    max_health_checks = int(settings.get("max_health_checks", 1500))

    if skip_health_check:
        alive = servers
        print("Health check skipped")
    else:
        pool = servers[:max_health_checks]
        print(f"Health check (TCP) for {len(pool)} servers (of {len(servers)} parsed)...")
        alive = filter_alive(pool, connect_timeout, health_workers)
        print(f"Alive: {len(alive)} / {len(servers)}")

    bs_alive = [s for s in alive if s.bypass == "БС"]
    cs_alive = [s for s in alive if s.bypass == "ЧС"]
    all_alive = alive

    wl_uris = [s.uri for s in bs_alive[:max_wl]]
    bl_uris = [s.uri for s in cs_alive[:max_bl]]
    all_uris = [s.uri for s in all_alive[:max_all]]

    clear_output_dir(out_dir)

    files_map = {
        f"{SUB_WL}.txt": wl_uris,
        f"{SUB_BL}.txt": bl_uris,
        f"{SUB_ALL}.txt": all_uris,
    }
    written: list[str] = []
    for fname, uris in files_map.items():
        path = out_dir / fname
        write_subscription(path, uris)
        written.append(str(path.relative_to(ROOT)))

    stats = {
        "total_parsed": len(servers),
        "alive": len(alive),
        "wl": len(wl_uris),
        "bl": len(bl_uris),
        "all": len(all_uris),
        "skipped_parse": skipped,
    }
    print(json.dumps(stats, ensure_ascii=False))
    return {"stats": stats, "files": written}


def main() -> int:
    parser = argparse.ArgumentParser(description="VPN subscription collector")
    parser.add_argument(
        "--sources",
        type=Path,
        default=ROOT / "config" / "sources.yaml",
    )
    parser.add_argument(
        "--classification",
        type=Path,
        default=ROOT / "config" / "classification.yaml",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Не загружать сеть; использовать встроенные тестовые URI",
    )
    args = parser.parse_args()

    samples = None
    if args.offline:
        vmess_sample = (
            "vmess://"
            + base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "v": "2",
                        "ps": "FI Finland mobile",
                        "add": "9.9.9.9",
                        "port": "443",
                        "id": "00000000-0000-0000-0000-000000000001",
                    }
                ).encode()
            )
            .decode()
            .rstrip("=")
        )
        samples = [
            "vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443?encryption=none#DE%20Whitelist%20BS",
            "trojan://password@nl.example.nl:443#NL%20blacklist%20CS",
            vmess_sample,
        ]

    try:
        collect(
            args.sources,
            args.classification,
            offline_samples=samples,
            skip_health_check=args.offline,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
