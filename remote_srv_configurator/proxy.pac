// example proxy auto config file
// https://forum.vivaldi.net/topic/104578/socks5-proxy-for-only-a-few-domains/5
function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, ".example.com")) return "SOCKS5 192.168.0.1:8055";
  if (dnsDomainIs(host, ".example.org")) return "SOCKS5 192.168.0.1:8055";
  return "DIRECT";
}
