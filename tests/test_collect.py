"""Тесты парсера подписок (без сети)."""

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from collect import (  # noqa: E402
    classify_bypass,
    decode_subscription_body,
    detect_country,
    extract_lines,
    parse_uri,
    process_uri,
    rename_uri,
)

SAMPLE_VMESS = (
    "vmess://"
    + base64.urlsafe_b64encode(
        json.dumps(
            {
                "v": "2",
                "ps": "FI Finland mobile",
                "add": "5.5.6.7",
                "port": "443",
                "id": "00000000-0000-0000-0000-000000000001",
            }
        ).encode()
    )
    .decode()
    .rstrip("=")
)


def test_decode_plain_and_base64():
    plain = "vless://uuid@1.2.3.4:443#test\n"
    assert "vless://" in decode_subscription_body(plain)
    b64 = base64.b64encode(plain.encode()).decode()
    assert "vless://" in decode_subscription_body(b64)


def test_extract_lines():
    body = "# comment\n\nvless://a@1.1.1.1:443#\n"
    lines = extract_lines(body)
    assert len(lines) == 1
    assert lines[0].startswith("vless://")


def test_parse_vless_trojan_vmess():
    vless = "vless://uuid@8.8.8.8:443?encryption=none#DE%20test"
    assert parse_uri(vless) == ("vless", "8.8.8.8", 443, "DE test")
    trojan = "trojan://pass@nl.host.example:443#NL%20node"
    scheme, host, port, name = parse_uri(trojan)
    assert scheme == "trojan"
    assert host == "nl.host.example"
    assert port == 443
    assert parse_uri(SAMPLE_VMESS)[0] == "vmess"


def test_classify_bypass():
    assert classify_bypass("MTS mobile whitelist", ["mobile"], ["black"], "ЧС") == "БС"
    assert classify_bypass("blacklist node", ["mobile"], ["black"], "ЧС") == "ЧС"
    assert classify_bypass("generic", ["mobile"], ["black"], "ЧС") == "ЧС"


def test_detect_country_flag_and_tld():
    names = {"DE": ["Germany", "🇩🇪"], "NL": ["Netherlands", "🇳🇱"], "UNKNOWN": ["Unknown", ""]}
    tld = {"de": "DE", "nl": "NL"}
    cc, name, flag = detect_country("🇳🇱 fast", "x.com", names, tld)
    assert cc == "NL"
    assert "Netherlands" in name
    cc2, _, _ = detect_country("node", "srv.example.de", names, tld)
    assert cc2 == "DE"


def test_process_uri_rename():
    cls = {
        "bypass_bs": ["whitelist", "mobile"],
        "bypass_cs": ["blacklist"],
        "default_bypass": "ЧС",
        "country_names": {
            "DE": ["Germany", "🇩🇪"],
            "NL": ["Netherlands", "🇳🇱"],
            "FI": ["Finland", "🇫🇮"],
            "UNKNOWN": ["Unknown", ""],
        },
        "tld_country": {"de": "DE"},
    }
    uri = "vless://uuid@1.2.3.4:443#DE%20Whitelist%20node"
    srv = process_uri(
        uri,
        cls["bypass_bs"],
        cls["bypass_cs"],
        cls["default_bypass"],
        {k.upper(): v for k, v in cls["country_names"].items()},
        cls["tld_country"],
    )
    assert srv is not None
    assert srv.bypass == "БС"
    assert "Germany" in srv.display_name or "DE" in srv.display_name
    assert "БС" in srv.uri or "%D0%" in srv.uri  # url-encoded Cyrillic


def test_rename_vmess_ps():
    out = rename_uri(SAMPLE_VMESS, "🇫🇮 Finland БС")
    assert out.startswith("vmess://")
    payload = out.split("://", 1)[1]
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    assert data["ps"] == "🇫🇮 Finland БС"


@pytest.mark.parametrize(
    "scheme",
    ["hysteria2://token@1.1.1.1:443", "hy2://token@1.1.1.1:443", "ss://YWVzLTEyODpwc0AxLjEuMS4xOjgzODg#node"],
)
def test_parse_extra_schemes(scheme):
    assert parse_uri(scheme) is not None
