# subconverter

Utility to convert between various proxy subscription formats.

Clash/Mihomo REALITY conversion preserves the per-node
`reality-opts.support-x25519mlkem768` boolean, including an explicit `false`.
VLESS URI input can pass the same option as a query parameter. An omitted value
stays omitted, preserving the behavior of existing subscriptions. The option
is not a top-level Clash template setting.

Clash conversion requests upstream subscriptions with `User-Agent: clash.meta`
by default, so services such as Sub-Store return native YAML with these fields
instead of a lossy URI list. An explicit `ua` query parameter takes precedence.
Download caches are separated by User-Agent to keep negotiated formats apart.

Native Mihomo YAML/JSON input supports all 28 outbound types in the audited
Mihomo source, including SSH, ShadowQUIC, Sudoku, MASQUE, TrustTunnel, OpenVPN,
Tailscale, ZeroTier, EasyTier, GOST Relay and named built-in policies. With
`new_name=true`, the original node map is authoritative: nested options, explicit
false/zero/null values, strings, peer-only endpoints and future fields survive
without reconstruction by the legacy model. Explicit conversion flags and node
renaming still apply; renamed `dialer-proxy` references follow the target node.
String types use quotes rather than explicit YAML tags.

This is native configuration conversion, not implementation of these network
protocols. The receiving Mihomo core must support the protocol and any required
build features. New protocol support does not create new share-URI formats or
translations to clients that cannot represent them. Existing URI importers and
legacy target exporters retain their protocol-specific behavior.

See [the protocol and parameter audit](docs/mihomo-support.md) and the pinned,
machine-readable [option schema](scripts/mihomo_schema.json).

[![Build Status](https://github.com/metacubex/subconverter/actions/workflows/build.yml/badge.svg)](https://github.com/metacubex/subconverter/actions)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/metacubex/subconverter.svg)](https://github.com/metacubex/subconverter/tags)
[![GitHub release](https://img.shields.io/github/release/metacubex/subconverter.svg)](https://github.com/metacubex/subconverter/releases)
[![GitHub license](https://img.shields.io/github/license/metacubex/subconverter.svg)](https://github.com/metacubex/subconverter/blob/master/LICENSE)

[Docker README](https://github.com/metacubex/subconverter/blob/master/README-docker.md)

[中文文档](https://github.com/metacubex/subconverter/blob/master/README-cn.md)

- [subconverter](#subconverter)
  - [Supported Types](#supported-types)
  - [Quick Usage](#quick-usage)
    - [Access Interface](#access-interface)
    - [Description](#description)
  - [Advanced Usage](#advanced-usage)
  - [Auto Upload](#auto-upload)

## Supported Types

| Type         | As Source  | As Target    | Target Name |
| ------------ | :--------: | :----------: | ----------- |
| Clash        |     ✓      |      ✓       | clash       |
| ClashR       |     ✓      |      ✓       | clashr      |
| Quantumult   |     ✓      |      ✓       | quan        |
| Quantumult X |     ✓      |      ✓       | quanx       |
| Loon         |     ✓      |      ✓       | loon        |
| SS (SIP002)  |     ✓      |      ✓       | ss          |
| SS Android   |     ✓      |      ✓       | sssub       |
| SSD          |     ✓      |      ✓       | ssd         |
| SSR          |     ✓      |      ✓       | ssr         |
| Surfboard    |     ✓      |      ✓       | surfboard   |
| Surge 2      |     ✓      |      ✓       | surge&ver=2 |
| Surge 3      |     ✓      |      ✓       | surge&ver=3 |
| Surge 4      |     ✓      |      ✓       | surge&ver=4 |
| V2Ray        |     ✓      |      ✓       | v2ray       |
| Telegram-liked HTTP/Socks 5 links |     ✓      |      ×       | Only as source |

Notice:

1. Shadowrocket users should use `ss`, `ssr` or `v2ray` as target.

2. You can add `&remark=` to Telegram-liked HTTP/Socks 5 links to set a remark for this node. For example:

   - tg://http?server=1.2.3.4&port=233&user=user&pass=pass&remark=Example

   - https://t.me/http?server=1.2.3.4&port=233&user=user&pass=pass&remark=Example


---

## Quick Usage

> Using default groups and rulesets configuration directly, without changing any settings

### Access Interface

```txt
http://127.0.0.1:25500/sub?target=%TARGET%&url=%URL%&config=%CONFIG%
```

### Description

| Argument | Required | Example | Description |
| -------- | :------: | :------ | ----------- |
| target   | Yes      | clash   | Target subscription type. Acquire from Target Name in [Supported Types](#supported-types). |
| url      | Yes      | https%3A%2F%2Fwww.xxx.com | Subscription to convert. Supports URLs and file paths. Process with [URLEncode](https://www.urlencoder.org/) first. |
| config   | No       | https%3A%2F%2Fwww.xxx.com | External configuration file path. Supports URLs and file paths. Process with [URLEncode](https://www.urlencoder.org/) first. More examples can be found in [this](https://github.com/lzdnico/subconverteriniexample) repository. |

If you need to merge two or more subscription, you should join them with '|' before the URLEncode process.

Example:

```txt
You have 2 subscriptions and you want to merge them and generate a Clash subscription:
1. https://dler.cloud/subscribe/ABCDE?clash=vmess
2. https://rich.cloud/subscribe/ABCDE?clash=vmess

First use '|' to separate 2 subscriptions:
https://dler.cloud/subscribe/ABCDE?clash=vmess|https://rich.cloud/subscribe/ABCDE?clash=vmess

Then process it with URLEncode to get %URL%:
https%3A%2F%2Fdler.cloud%2Fsubscribe%2FABCDE%3Fclash%3Dvmess%7Chttps%3A%2F%2Frich.cloud%2Fsubscribe%2FABCDE%3Fclash%3Dvmess

Then fill %TARGET% and %URL% in Access Interface with actual values:
http://127.0.0.1:25500/sub?target=clash&url=https%3A%2F%2Fdler.cloud%2Fsubscribe%2FABCDE%3Fclash%3Dvmess%7Chttps%3A%2F%2Frich.cloud%2Fsubscribe%2FABCDE%3Fclash%3Dvmess

Finally subscribe this link in Clash and you are done!
```

---

## Advanced Usage

Please refer to [中文文档](https://github.com/metacubex/subconverter/blob/master/README-cn.md#%E8%BF%9B%E9%98%B6%E7%94%A8%E6%B3%95).

## Auto Upload

> Upload Gist automatically

Add a [Personal Access Token](https://github.com/settings/tokens/new) into [gistconf.ini](./gistconf.ini) in the root directory, then add `&upload=true` to the local subscription link, then when you access this link, the program will automatically update the content to Gist repository.

Example:

```ini
[common]
;uncomment the following line and enter your token to enable upload function
token = xxxxxxxxxxxxxxxxxxxxxxxx(Your Personal Access Token)
```
