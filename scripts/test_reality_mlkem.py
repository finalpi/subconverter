#!/usr/bin/env python3
"""Exercise the built converter over HTTP; all credentials are synthetic."""
import argparse
import base64
import copy
import http.server
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml
from test_mihomo_native import run_native_cases

FLAG = "support-x25519mlkem768"
MISSING = object()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_cases(endpoint, fixtures, fixture_url):
    base = {
        "name": "MLKEM-regression", "type": "vless", "server": "example.com",
        "port": 443, "uuid": "00000000-0000-4000-8000-000000000001",
        "tls": True, "network": "tcp", "flow": "xtls-rprx-vision",
        "servername": "example.com", "client-fingerprint": "chrome",
        "reality-opts": {"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "aabbccddeeff0011"},
    }

    def convert(node, name, options=None, expected_count=1):
        key = "/" + name + ".yaml"
        fixtures[key] = yaml.safe_dump({"proxies": [node]}).encode()
        args = {"target": "clash", "url": fixture_url + key,
                "list": "true", "insert": "false", "new_name": "true"}
        args.update(options or {})
        query = urllib.parse.urlencode(args)
        try:
            with urllib.request.urlopen(endpoint + "/sub?" + query, timeout=20) as r:
                body = r.read()
        except urllib.error.HTTPError as error:
            body = error.read()
            assert expected_count == 0 and error.code == 400 and (
                b"valid node info" in body or b"No nodes were found" in body), (name, body)
            return None
        assert b"!!str" not in body and b"!<tag:yaml.org,2002:str>" not in body and b"!<str>" not in body, name
        result = yaml.safe_load(body)
        nodes = result.get("proxies", result.get("Proxy", []))
        assert len(nodes) == expected_count, f"{name}: expected {expected_count} exported proxies"
        return nodes[0] if expected_count else None

    count = 0
    for label, value in [("true", True), ("false", False), ("unset", MISSING)]:
        node = copy.deepcopy(base)
        if value is not MISSING:
            node["reality-opts"][FLAG] = value
        for round_number in range(2):
            node = convert(node, f"{label}-{round_number}")
            opts = node["reality-opts"]
            assert opts["public-key"] == base["reality-opts"]["public-key"]
            assert opts["short-id"] == base["reality-opts"]["short-id"]
            assert node["flow"] == base["flow"]
            assert node["client-fingerprint"] == "chrome"
            if value is MISSING:
                assert FLAG not in opts, "unspecified legacy option must remain unspecified"
            else:
                assert FLAG in opts and type(opts[FLAG]) is bool and opts[FLAG] is value, f"{label}: boolean was dropped or changed"
            count += 1

    plain = copy.deepcopy(base)
    del plain["reality-opts"]
    assert "reality-opts" not in convert(plain, "plain-tls")
    count += 1

    for label, value in [("true", "true"), ("false", "false"), ("unset", None)]:
        params = {"type": "tcp", "security": "reality", "flow": "xtls-rprx-vision", "fp": "chrome",
                  "sni": "example.com", "pbk": base["reality-opts"]["public-key"], "sid": base["reality-opts"]["short-id"]}
        if value is not None:
            params[FLAG] = value
        uri = "vless://" + base["uuid"] + "@example.com:443?" + urllib.parse.urlencode(params) + "#URI-MLKEM"
        query = urllib.parse.urlencode({"target": "clash", "url": uri, "list": "true", "insert": "false", "new_name": "true"})
        with urllib.request.urlopen(endpoint + "/sub?" + query, timeout=20) as r:
            result = yaml.safe_load(r.read())
        opts = result.get("proxies", result.get("Proxy", []))[0]["reality-opts"]
        if value is None:
            assert FLAG not in opts
        else:
            assert type(opts.get(FLAG)) is bool and opts[FLAG] is (value == "true")
        count += 1
    # Sub-Store-style negotiation: generic clients receive a URI without ML-KEM.
    native = copy.deepcopy(base)
    native["reality-opts"][FLAG] = True
    native_yaml = yaml.safe_dump({"proxies": [native]}).encode()
    legacy_uri = ("vless://" + base["uuid"] + "@example.com:443?" +
                  urllib.parse.urlencode(params) + "#URI-MLKEM").encode()
    fixtures["/negotiated.yaml"] = lambda ua: native_yaml if ua == "clash.meta" else base64.b64encode(legacy_uri)
    for label, ua, expected in [("default", None, True), ("explicit-legacy", "legacy-client", MISSING),
                                ("explicit-native", "clash.meta", True), ("default-again", None, True)]:
        query = {"target": "clash", "url": fixture_url + "/negotiated.yaml",
                 "list": "true", "insert": "false", "new_name": "true"}
        if ua is not None:
            query["ua"] = ua
        with urllib.request.urlopen(endpoint + "/sub?" + urllib.parse.urlencode(query), timeout=20) as r:
            result = yaml.safe_load(r.read())
        opts = result["proxies"][0]["reality-opts"]
        if expected is MISSING:
            assert FLAG not in opts, f"{label}: explicit UA must not reuse the native YAML cache"
        else:
            assert opts.get(FLAG) is True, f"{label}: native YAML field lost during negotiation/cache"
        count += 1
    # Future fields require no named parser/exporter changes. Check YAML types,
    # nested known maps, independent nodes and multiple native round trips.
    future = {"enabled": False, "count": 0, "ratio": 1.25, "null-value": None,
              "numeric-string": "00123", "boolean-string": "false", "null-string": "null",
              "empty-string": "", "empty-list": [], "empty-map": {},
              "items": [False, 7, "007", None, {"deep": ["true", 2]}]}
    def typed(value):
        if isinstance(value, dict):
            return {key: typed(item) for key, item in value.items()}
        if isinstance(value, list):
            return [typed(item) for item in value]
        return (type(value).__name__, value)
    enriched = copy.deepcopy(base)
    enriched["future-option"] = future
    enriched["future-list"] = [future, "false", 3]
    enriched["reality-opts"]["future-reality"] = future
    enriched["ech-opts"] = {"enable": False, "future-ech": future}
    enriched["network"] = "ws"
    enriched["ws-opts"] = {"path": "/native", "headers": {"Host": "example.com", "X-Future": "false"}, "future-ws": future}
    for round_number in range(3):
        enriched = convert(enriched, f"future-round-{round_number}")
        assert typed(enriched["future-option"]) == typed(future), repr(enriched["future-option"])
        assert enriched["future-list"] == [future, "false", 3]
        assert enriched["reality-opts"]["future-reality"] == future
        assert enriched["ech-opts"]["future-ech"] == future
        assert enriched["ech-opts"]["enable"] is False
        assert enriched["ws-opts"]["future-ws"] == future
        assert enriched["ws-opts"]["headers"]["X-Future"] == "false"
        count += 1

    full_profile = convert(enriched, "future-full-profile", {"list": "false"})
    assert typed(full_profile["future-option"]) == typed(future)
    count += 1

    enriched.update({"udp": True, "tfo": True, "skip-cert-verify": True})
    renamed = convert(enriched, "future-overrides", {"rename": "MLKEM-regression@renamed",
                      "udp": "false", "tfo": "false", "scv": "false"})
    assert renamed["name"] == "renamed"
    assert renamed["udp"] is False and renamed["tfo"] is False and renamed["skip-cert-verify"] is False
    assert renamed["future-option"] == future
    count += 1

    for proxy_type, settings in [("ss", {"cipher": "aes-128-gcm", "password": "synthetic"}),
                                  ("vmess", {"uuid": base["uuid"], "alterId": 0, "cipher": "auto"}),
                                  ("trojan", {"password": "synthetic", "sni": "example.com"}),
                                  ("hysteria2", {"password": "synthetic", "sni": "example.com"}),
                                  ("tuic", {"uuid": base["uuid"], "password": "synthetic"}),
                                  ("anytls", {"password": "synthetic", "sni": "example.com"})]:
        node = {"name": "future-" + proxy_type, "type": proxy_type, "server": "example.com", "port": 443,
                "future-option": future, **settings}
        result = convert(node, "future-type-" + proxy_type)
        assert result["type"] == proxy_type and result["future-option"] == future
        assert "future-reality" not in result.get("reality-opts", {}), "fields leaked between nodes"
        count += 1

    # Existing normalizations and legacy transport output must remain effective.
    legacy = copy.deepcopy(base)
    legacy.update({"network": "ws", "ws-path": "/legacy", "ws-headers": {"Host": "example.com"},
                   "underlying-proxy": "DIRECT", "fast-open": True})
    normalized = convert(legacy, "future-normalized", {"tfo": "false"})
    assert normalized["ws-opts"]["path"] == "/legacy"
    assert normalized["dialer-proxy"] == "DIRECT" and normalized["tfo"] is False
    assert not any(k in normalized for k in ["ws-path", "ws-headers", "underlying-proxy", "fast-open"])
    deprecated = convert(normalized, "future-deprecated", {"new_name": "false"})
    assert deprecated["ws-path"] == "/legacy" and "ws-opts" not in deprecated
    count += 2

    # Mieru is a native Mihomo protocol, including range-only endpoints.
    mieru = {"name": "Mieru-regression", "type": "mieru", "server": "example.com", "port": 8443,
             "transport": "TCP", "username": "false", "password": "00123", "multiplexing": "LOW",
             "handshake-mode": "HANDSHAKE_NO_WAIT", "traffic-pattern": "synthetic",
             "udp": True, "future-option": future}
    for transport in ["TCP", "UDP"]:
        node = dict(mieru, transport=transport)
        for round_number in range(2):
            node = convert(node, f"mieru-{transport}-{round_number}")
            assert typed(node) == typed(dict(mieru, transport=transport)), node
            count += 1
    ranged = dict(mieru)
    ranged.pop("port")
    ranged["port-range"] = "8443-8449"
    for round_number in range(2):
        result = convert(ranged, f"mieru-range-{round_number}")
        assert typed(result) == typed(ranged) and "port" not in result
        ranged = result
        count += 1
    overridden = convert(mieru, "mieru-overrides", {"rename": "Mieru-regression@renamed", "udp": "false"})
    assert overridden["name"] == "renamed" and overridden["udp"] is False
    assert overridden["password"] == "00123" and overridden["username"] == "false"
    count += 1
    for label, settings in [("both-ports", {"port-range": "8443-8449"}), ("missing-user", {"username": ""}),
                            ("bad-transport", {"transport": "QUIC"}), ("bad-port", {"port": 65536}),
                            ("reverse-range", {"port": None, "port-range": "8449-8443"}),
                            ("bad-range", {"port": None, "port-range": "0-65536"})]:
        convert(dict(mieru, **settings), "mieru-invalid-" + label, expected_count=0)
        count += 1
    for label, value in [("null", None), ("empty", "")]:
        node = convert(dict(mieru, **{"port-range": value}), "mieru-empty-range-" + label)
        assert node["port"] == 8443, node
        count += 1
    count += run_native_cases(endpoint, fixtures, fixture_url)
    print(json.dumps({"result": "REALITY_MLKEM_REGRESSION_PASSED", "checks": count}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--engine", default="docker", choices=["docker", "podman"])
    args = parser.parse_args()
    fixtures = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = fixtures.get(self.path)
            if body is None:
                self.send_error(404)
                return
            if callable(body):
                body = body(self.headers.get("User-Agent", ""))
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with tempfile.TemporaryDirectory(prefix="subconverter-mlkem-") as scratch:
        port = free_port()
        endpoint = f"http://127.0.0.1:{port}"
        Path(scratch, "pref.ini").write_text(
            "[common]\napi_mode=false\nenable_insert=false\nbase_path=/base\nclash_rule_base=/base/base/clash.yml\n"
            f"[server]\nlisten=127.0.0.1\nport={port}\n"
            "[advanced]\nenable_cache=true\ncache_subscription=300\n", encoding="utf-8")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        name = "subconverter-mlkem-" + uuid.uuid4().hex[:12]
        try:
            subprocess.run([args.engine, "run", "--detach", "--rm", "--name", name,
                            "--network", "host", "--volume", str(Path(scratch, "pref.ini")) + ":/base/pref.ini:ro",
                            args.image], check=True, stdout=subprocess.DEVNULL)
            deadline = time.monotonic() + 25
            while True:
                try:
                    urllib.request.urlopen(endpoint + "/version", timeout=1).close()
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("regression converter did not start")
                    time.sleep(.2)
            run_cases(endpoint, fixtures, f"http://127.0.0.1:{server.server_address[1]}")
        except Exception:
            subprocess.run([args.engine, "logs", "--tail", "40", name], check=False)
            raise
        finally:
            server.shutdown()
            server.server_close()
            subprocess.run([args.engine, "rm", "--force", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
