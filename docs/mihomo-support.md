# Mihomo 协议与参数兼容范围

核对日期：2026-11-02。依据 Mihomo 官方源码
[`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8)，
并使用官方稳定版 v1.19.33 校验代表性配置。

## 协议清单

下表的支持指原生 Mihomo YAML/JSON 输入并输出为 Clash/Mihomo 配置。
`target=clash&new_name=true` 使用完整原生节点保留逻辑。

| 范围 | 类型 | 当前行为 |
| --- | --- | --- |
| 已有协议 | ss、ssr、socks5、http、vmess、vless、snell、trojan、hysteria、hysteria2、wireguard、tuic、anytls、mieru | 保留完整节点参数，继续提供已有的其他目标格式转换 |
| 新增代理协议 | ssh、shadowquic、gost-relay、sudoku、masque、trusttunnel | 保留原生节点，支持筛选、改名、分组和链式引用 |
| 新增 VPN / 组网类型 | openvpn、tailscale、zerotier、easytier | 保留原生节点，包括无顶层 server/port 的配置 |
| 新增内置出站 | direct、dns、reject、rematch | 保留命名出站及专属参数，不生成虚假的端点 |

共 28 种类型。未知类型不会被猜测成其他协议。
这些类型的运行能力取决于客户端内核及构建选项；例如组网类型可能需要
客户端状态目录、认证或特定构建功能。转换服务不会安装或启动这些协议。

## 参数保留规则

现代 Mihomo 配置以原节点为准，不再先用旧字段模型重建后补缺失项。
通用字段、协议字段、TLS、REALITY、ECH、SMUX、传输层配置和嵌套 peer
均保留原有值与 YAML 类型；未知扩展字段也按相同规则保留。

- 显式的 `false`、`0`、空字符串、空集合、`null` 与字符串形式的这些值分别保留。
- HTTP 多路径、多值头，gRPC、XHTTP、mKCP、Mekya、JLS、ShadowTLS、Restls、TLSMirror 等原生配置无需逐字段添加兼容分支。
- TUIC 和 Hysteria 的 `fast-open` 独立于 TCP `tfo`，分别保留。
- WireGuard 多 peer 配置不要求顶层端口；内置出站和组网类型也不补造端口。
- 改名、排除、排序、分组以及显式 `udp` / `tfo` / `scv` 转换设置继续生效。
  `scv` 只覆盖具有该配置项的协议；节点改名同步更新其他节点的 `dialer-proxy` 引用。
- 旧别名 `underlying-proxy`、WebSocket 旧字段和 TUIC `heartbeat_interval` 按对应规则规范化。

这不表示任意参数组合都有效。例如不支持的枚举值、无效证书、错误密钥和
协议之间不兼容的选项仍需由 Mihomo 检查，转换器不会修造缺失的凭据。

`new_name=false` 的已有协议继续使用旧目标字段转换；新增原生类型仍保留
协议身份，但旧版 Clash 本身不因此获得运行这些协议的能力。
分享 URI 继续按既有导入器及其格式定义处理，本次不会把未知查询参数直接
转换成未经定义的配置字段。

## 可复核清单与测试

[`scripts/mihomo_schema.json`](../scripts/mihomo_schema.json) 从官方 Go AST 提取
28 种协议及 60 个带配置标签的结构体，包含 688 处字段声明。该数量包含
不同结构体中的同名字段，不是 688 个互不重复的参数。

重新生成清单：

```powershell
go run scripts/audit_mihomo.go --source <Mihomo源码目录> --out scripts/mihomo_schema.json
```

回归测试逐协议检查 YAML、JSON 和多次转换后的字段及类型，另外检查
无顶层端点、完整配置输出、类型筛选、改名后的链式引用和显式转换选项。
模式探针使用合成参数值，验证数据保留，不用它们声称网络连接可用。

CI 另用通过发布摘要校验的官方 Mihomo v1.19.33，对转换后的 23 种代表性
配置运行 `-t`。涉及机器状态或额外凭据的 OpenVPN、MASQUE 和三种组网
类型只做转换数据校验，不在 CI 启动或注册网络服务。
