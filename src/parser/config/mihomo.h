#ifndef MIHOMO_H_INCLUDED
#define MIHOMO_H_INCLUDED

#include "proxy.h"

// Audited against MetaCubeX/mihomo 3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8
// adapter/parser.go. Native YAML keeps each protocol's complete option map.
inline bool isMihomoProxyType(const String &type)
{
    static const StringArray types = {
        "ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan",
        "hysteria", "hysteria2", "wireguard", "tuic", "shadowquic", "gost-relay",
        "direct", "dns", "reject", "rematch", "ssh", "mieru", "anytls", "sudoku",
        "masque", "trusttunnel", "openvpn", "tailscale", "zerotier", "easytier"
    };
    for(const auto &candidate : types)
        if(type == candidate) return true;
    return false;
}

inline bool isMihomoTlsType(const String &type)
{
    static const StringArray types = {
        "http", "socks5", "vmess", "vless", "trojan", "hysteria", "hysteria2",
        "tuic", "gost-relay", "anytls", "masque", "trusttunnel"
    };
    for(const auto &candidate : types)
        if(type == candidate) return true;
    return false;
}

#endif
