# ip-reputation

A free, daily-rebuilt list of IP ranges that should not be trusted as ordinary visitors: Tor exit
nodes, VPN providers, datacenter / cloud / hosting ranges and known abusive or open proxies,
for IPv4 and IPv6. Used by Actify to decide who gets a Turnstile check before submitting a form.

## Download

From the [`latest` release](../../releases/tag/latest):

| File | Content |
| --- | --- |
| `ipv4.txt.gz` | one merged range per line, `start end` as decimal integers, sorted, non-overlapping |
| `ipv6.txt.gz` | same, `start end` as 32 hex digits |
| `meta.json` | build time, per-file `sha256` and range count, per-source entry count |

```
https://github.com/Eliott-Markus/ip-reputation/releases/download/latest/ipv4.txt.gz
https://github.com/Eliott-Markus/ip-reputation/releases/download/latest/ipv6.txt.gz
https://github.com/Eliott-Markus/ip-reputation/releases/download/latest/meta.json
```

Check each file against `meta.json` (`sha256`) before using it.

## How it is built

`build.py` (Python standard library only) runs every day at 03:17 UTC in GitHub Actions. It **publishes
nothing** when a source cannot be downloaded or is cut short, when a source has fewer than half the
entries of the previous build, or when a known residential address ends up listed. The previous files
then stay in place. `meta.json` in this repository keeps the history of the counts.

## Sources

Each list keeps the terms of its publisher; this repository only merges them.

| Source | What | Publisher |
| --- | --- | --- |
| [Tor bulk exit list](https://check.torproject.org/torbulkexitlist), [Onionoo](https://onionoo.torproject.org/) | Tor exit relays, IPv4 + IPv6 | The Tor Project |
| [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) | VPN providers, datacenters, IPv4 + IPv6 | X4BNet |
| [FireHOL level 1](https://iplists.firehol.org/?ipset=firehol_level1), [FireHOL proxies](https://iplists.firehol.org/?ipset=firehol_proxies) | blocklist and known proxies (aggregated from their listed sources) | FireHOL |
| [AWS](https://ip-ranges.amazonaws.com/ip-ranges.json), [Google Cloud](https://www.gstatic.com/ipranges/cloud.json), [Oracle Cloud](https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json), [DigitalOcean](https://digitalocean.com/geo/google.csv), [Linode](https://geoip.linode.com/) | cloud ranges published by the providers | each provider |

Not covered: residential proxies that are not on the FireHOL lists, and most residential IPv6.
