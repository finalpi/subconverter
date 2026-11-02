"""Validate representative converted configurations with the real Mihomo core."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile

import yaml


def valid_nodes():
    uuid = "00000000-0000-4000-8000-000000000001"
    settings = {
        "ss": {"cipher": "aes-128-gcm", "password": "false"},
        "ssr": {"cipher": "aes-128-cfb", "password": "00123", "protocol": "origin", "obfs": "plain"},
        "http": {"username": "false", "password": "00123"},
        "socks5": {"username": "false", "password": "00123", "udp": True},
        "vmess": {"uuid": uuid, "alterId": 0, "cipher": "auto", "network": "tcp", "tls": True},
        "vless": {"uuid": uuid, "network": "ws", "tls": True, "ws-opts": {"path": "/synthetic", "headers": {"Host": "example.com"}}},
        "snell": {"psk": "synthetic-password", "version": 3, "udp": True},
        "trojan": {"password": "false", "sni": "example.com"},
        "hysteria": {"auth-str": "synthetic", "up": "10 Mbps", "down": "20 Mbps", "fast-open": True},
        "hysteria2": {"password": "synthetic", "sni": "example.com"},
        "tuic": {"uuid": uuid, "password": "synthetic", "fast-open": True, "tfo": False},
        "anytls": {"password": "00123", "sni": "example.com"},
        "mieru": {"username": "false", "password": "00123", "transport": "TCP", "multiplexing": "MULTIPLEXING_LOW"},
        "ssh": {"username": "false", "password": "00123", "host-key-algorithms": ["ssh-ed25519"]},
        "gost-relay": {"username": "false", "password": "00123"},
        "shadowquic": {"username": "false", "password": "00123", "sni": "example.com"},
        "trusttunnel": {"username": "false", "password": "00123", "sni": "example.com"},
        "sudoku": {"key": "synthetic-password"},
        "wireguard": {"private-key": base64.b64encode(bytes([1]) * 32).decode(), "ip": "10.0.0.2",
                      "peers": [{"server": "127.0.0.1", "port": 51820, "public-key": base64.b64encode(bytes([2]) * 32).decode(),
                                 "allowed-ips": ["0.0.0.0/0"]}]},
        "direct": {}, "dns": {}, "reject": {}, "rematch": {"target-rematch-name": "synthetic-rematch"},
    }
    nodes = []
    for protocol, options in settings.items():
        node = {"name": "validate-" + protocol, "type": protocol, **options}
        if protocol not in ["wireguard", "direct", "dns", "reject", "rematch"]:
            node.update({"server": "127.0.0.1", "port": 443})
        nodes.append(node)
    return nodes


def validate_nodes(binary, nodes):
    # This checks parsing only. No listeners, TUN, service changes or test
    # connections; VPN/mesh protocols requiring machine state are schema-tested.
    profile = {"mixed-port": 0, "allow-lan": False, "mode": "rule", "log-level": "error",
               "proxies": nodes, "proxy-groups": [{"name": "synthetic-selector", "type": "select", "proxies": [n["name"] for n in nodes]}],
               "rules": ["MATCH,DIRECT"]}
    with tempfile.TemporaryDirectory(prefix="mihomo-native-validation-") as scratch:
        path = Path(scratch) / "config.yaml"
        path.write_text(yaml.safe_dump(profile, allow_unicode=True), encoding="utf-8")
        result = subprocess.run([binary, "-t", "-d", scratch, "-f", str(path)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
    print(json.dumps({"result": "MIHOMO_CORE_VALIDATION_PASSED", "protocols": len(nodes)}), flush=True)


if __name__ == "__main__":
    import sys
    validate_nodes(sys.argv[1], valid_nodes())
