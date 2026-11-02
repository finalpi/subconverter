"""Native conversion contract tests, driven by the audited Mihomo Go schema.

Schema probes contain synthetic values and test transport fidelity, not whether
every combination is a runnable server configuration.
"""
import copy
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

import yaml


def run_native_cases(endpoint, fixtures, fixture_url):
    audit = json.loads(Path(__file__).with_name("mihomo_schema.json").read_text(encoding="utf-8"))
    structs = audit["structs"]
    count = 0

    def fields(name, visiting=()):
        if name not in structs or name in visiting:
            return {}
        result = {}
        for embed in structs[name].get("embeds", []):
            result.update(fields(embed.lstrip("*"), (*visiting, name)))
        result.update(structs[name]["fields"])
        return result

    def probe(typ, visiting=()):
        typ = typ.lstrip("*")
        if typ.startswith("[]"):
            return [probe(typ[2:], visiting)]
        if typ.startswith("[") and "]" in typ and not typ.startswith("[]"):
            size, item = typ[1:].split("]", 1)
            return [probe(item, visiting)] * int(size)
        if typ in structs and typ not in visiting:
            return {key: probe(field["go_type"], (*visiting, typ)) for key, field in fields(typ).items()}
        if typ == "bool":
            return False
        if typ.startswith(("int", "uint", "float")):
            return 0
        if typ.startswith("map[") or typ in ["any", "interface{}"]:
            return {"nested": [False, None, "00123", 2], "boolean-string": "false"}
        return "false"

    def typed(value):
        if isinstance(value, dict):
            return {key: typed(item) for key, item in value.items()}
        if isinstance(value, list):
            return [typed(item) for item in value]
        return type(value).__name__, value

    def request(nodes, label, options=None, json_input=False, legacy=False):
        key = "/native-" + label + (".json" if json_input else ".yaml")
        document = {"version": "synthetic-schema-probe", "Proxy" if legacy else "proxies": nodes}
        fixtures[key] = (json.dumps(document) if json_input else yaml.safe_dump(document)).encode()
        query = {"target": "clash", "url": fixture_url + key, "list": "true", "insert": "false", "new_name": "true"}
        query.update(options or {})
        with urllib.request.urlopen(endpoint + "/sub?" + urllib.parse.urlencode(query), timeout=20) as response:
            body = response.read()
        assert not any(tag in body for tag in [b"!!str", b"!<tag:yaml.org,2002:str>", b"!<str>"]), label
        result = yaml.safe_load(body)
        return result, result.get("proxies", result.get("Proxy", []))

    for protocol, entry in audit["protocols"].items():
        node = {key: probe(field["go_type"]) for key, field in fields(entry["option_struct"]).items()}
        node.update({"name": "native-" + protocol, "type": protocol})
        if "server" in node:
            node["server"] = "example.com"
        if "port" in node:
            node["port"] = 443
        if protocol == "mieru":
            node.update({"username": "false", "password": "00123", "transport": "TCP", "port-range": ""})
        if protocol == "tuic":
            node.update({"fast-open": True, "tfo": False})
        node["future-option"] = {"nested": [False, "false", "00123", None, {}, []], "ratio": 1.25}
        expected = copy.deepcopy(node)
        # Deprecated WS aliases normalize to ws-opts, which is already present
        # with the same schema-probe values. Alias behavior has dedicated tests.
        expected.pop("ws-headers", None)
        expected.pop("ws-path", None)
        for round_number in range(2):
            _, converted = request([node], f"{protocol}-{round_number}", json_input=round_number == 1)
            assert len(converted) == 1, protocol
            node = converted[0]
            assert typed(node) == typed(expected), (protocol, expected, node)
            count += 1

    # Endpoints are not mandatory for built-in policies, peer-only WG or mesh.
    for protocol in ["direct", "dns", "reject", "rematch", "tailscale", "zerotier", "easytier", "wireguard"]:
        node = {"name": "no-endpoint-" + protocol, "type": protocol, "future-option": "00123"}
        if protocol == "wireguard":
            node.update({"private-key": "synthetic", "ip": "10.0.0.2", "peers": [{"server": "example.com", "port": 51820,
                         "public-key": "synthetic", "reserved": [0, 1, 2], "allowed-ips": ["0.0.0.0/0"]}]})
        _, converted = request([node], "no-endpoint-" + protocol, legacy=True)
        assert typed(converted) == typed([node]), protocol
        count += 1

    # Legacy parsing used to recreate these fields with defaults or truncate them.
    transport_node = {"name": "new-transport", "type": "vless", "server": "example.com", "port": "00443",
                      "uuid": "00000000-0000-4000-8000-000000000001", "network": "xhttp", "tls": True,
                      "flow": "", "xhttp-opts": {"mode": "packet-up", "path": "/synthetic", "extra": {"headers": {"X-Value": "false"}}},
                      "http-opts": {"method": "PATCH", "path": ["/one", "/two"], "headers": {"Host": ["a.example", "b.example"]}},
                      "reality-opts": {"public-key": "synthetic", "short-id": "00123", "support-x25519mlkem768": False},
                      "smux": {"enabled": False, "brutal-opts": {"enabled": False, "up": 0, "down": 0}}}
    _, converted = request([transport_node], "transport-fidelity", {"list": "false"})
    assert typed(converted) == typed([transport_node])
    count += 1

    # Explicit flags, renaming, native protocol type filters and chain references.
    ssh = {"name": "ssh-old", "type": "ssh", "server": "example.com", "port": 22,
           "username": "false", "password": "00123", "host-key-algorithms": ["ssh-ed25519"]}
    chained = {"name": "vless-old", "type": "vless", "server": "example.com", "port": 443,
               "uuid": "00000000-0000-4000-8000-000000000001", "dialer-proxy": "ssh-old",
               "udp": True, "tfo": True, "skip-cert-verify": True}
    fixtures["/native-groups.ini"] = (
        "[custom]\nenable_rule_generator=false\n"
        "custom_proxy_group=SSH`select`!!TYPE=^SSH$\n"
        "custom_proxy_group=VLESS`select`!!TYPE=^VLESS$\n").encode()
    document, converted = request([ssh, chained], "group-chain", {"list": "false", "rename": "ssh-old@ssh-new",
                                   "udp": "false", "tfo": "false", "scv": "false", "config": fixture_url + "/native-groups.ini"})
    groups = {group["name"]: group["proxies"] for group in document["proxy-groups"]}
    assert groups["SSH"] == ["ssh-new"] and groups["VLESS"] == ["vless-old"], groups
    assert converted[1]["dialer-proxy"] == "ssh-new", converted
    assert converted[1]["udp"] is False and converted[1]["tfo"] is False and converted[1]["skip-cert-verify"] is False
    assert converted[0]["password"] == "00123" and "skip-cert-verify" not in converted[0]
    count += 1
    binary = os.environ.get("MIHOMO_TEST_BINARY")
    if binary:
        from validate_mihomo_output import valid_nodes, validate_nodes
        valid = valid_nodes()
        _, converted = request(valid, "real-core")
        assert len(converted) == len(valid)
        validate_nodes(binary, converted)
        count += 1
    print(json.dumps({"result": "MIHOMO_NATIVE_SCHEMA_PASSED", "protocols": len(audit["protocols"]),
                      "checks": count, "source_revision": audit["source"]["revision"]}), flush=True)
    return count
