"""Tests for subscription collector (no real network)."""

import base64
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from collect import (  # noqa: E402
    SUB_ALL,
    SUB_BL,
    SUB_WL,
    classify_bypass,
    collect,
    decode_subscription_body,
    detect_country,
    extract_lines,
    parse_uri,
    process_uri,
    rename_uri,
    tcp_reachable,
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
    assert classify_bypass("MTS mobile whitelist", ["mobile"], ["black"], "\u0427\u0421") == "\u0411\u0421"
    assert classify_bypass("blacklist node", ["mobile"], ["black"], "\u0427\u0421") == "\u0427\u0421"


def test_detect_country_flag_and_tld():
    names = {
        "DE": ["Germany", "\U0001f1e9\U0001f1ea"],
        "NL": ["Netherlands", "\U0001f1f3\U0001f1f1"],
        "UNKNOWN": ["Unknown", ""],
    }
    tld = {"de": "DE", "nl": "NL"}
    cc, name, flag = detect_country("NL fast", "x.com", names, tld)
    assert cc == "NL"
    assert "Netherlands" in name
    cc2, _, _ = detect_country("node", "srv.example.de", names, tld)
    assert cc2 == "DE"


def test_process_uri_country_only_name():
    cls = {
        "bypass_bs": ["whitelist", "mobile"],
        "bypass_cs": ["blacklist"],
        "default_bypass": "\u0427\u0421",
        "country_names": {
            "DE": ["Germany", "\U0001f1e9\U0001f1ea"],
            "NL": ["Netherlands", "\U0001f1f3\U0001f1f1"],
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
    assert srv.bypass == "\u0411\u0421"
    assert "\u0411\u0421" not in srv.display_name
    assert "\u0427\u0421" not in srv.display_name
    assert "Germany" in srv.display_name


def test_rename_vmess_ps():
    out = rename_uri(SAMPLE_VMESS, "Finland")
    payload = out.split("://", 1)[1]
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    assert data["ps"] == "Finland"


@patch("collect.tcp_reachable", return_value=True)
def test_collect_writes_three_files(mock_tcp, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "collect.ROOT",
        tmp_path,
    )
    out = tmp_path / "output"
    sources = tmp_path / "sources.yaml"
    sources.write_text(
        "settings:\n  output_dir: output\n  max_wl: 100\n  max_bl: 100\n  max_all: 200\nsources: []\n",
        encoding="utf-8",
    )
    classification = ROOT / "config" / "classification.yaml"
    vmess_sample = (
        "vmess://"
        + base64.urlsafe_b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "FI",
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
        "vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443?encryption=none#DE%20Whitelist",
        "trojan://password@nl.example.nl:443#NL%20blacklist",
        vmess_sample,
    ]
    result = collect(sources, classification, offline_samples=samples, skip_health_check=False)
    assert mock_tcp.called
    assert (out / f"{SUB_WL}.txt").exists()
    assert (out / f"{SUB_BL}.txt").exists()
    assert (out / f"{SUB_ALL}.txt").exists()
    assert len(list(out.iterdir())) == 3
    assert result["stats"]["wl"] <= 100


def test_tcp_reachable_mock():
    with patch("collect.socket.create_connection") as m:
        m.return_value.__enter__.return_value = object()
        assert tcp_reachable("1.1.1.1", 443, 1.0) is True
    with patch("collect.socket.create_connection", side_effect=OSError):
        assert tcp_reachable("1.1.1.1", 443, 1.0) is False