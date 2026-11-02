#!/usr/bin/env python3
"""Exercise the built converter over HTTP; all credentials are synthetic."""
import argparse
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

    def convert(node, name):
        key = "/" + name + ".yaml"
        fixtures[key] = yaml.safe_dump({"proxies": [node]}).encode()
        query = urllib.parse.urlencode({"target": "clash", "url": fixture_url + key,
                                        "list": "true", "insert": "false", "new_name": "true"})
        with urllib.request.urlopen(endpoint + "/sub?" + query, timeout=20) as r:
            result = yaml.safe_load(r.read())
        nodes = result.get("proxies", result.get("Proxy", []))
        assert len(nodes) == 1, f"{name}: expected one exported proxy"
        return nodes[0]

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
            f"[server]\nlisten=127.0.0.1\nport={port}\n", encoding="utf-8")
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
