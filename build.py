#!/usr/bin/env python3
"""Build the IP reputation dataset: Tor exits, VPN, datacenter/cloud and known-proxy ranges, IPv4 + IPv6.

Writes dist/ipv4.txt.gz, dist/ipv6.txt.gz (one merged range per line: "start end", decimal for IPv4,
32 hex digits for IPv6, sorted) and dist/meta.json (per-source counts, sha256 of each file).

Refuses to publish (exit 1) when a source fails, comes in under half of its previous count
(previous meta.json given as argv[1]), or when a known residential address ends up listed.
Standard library only.
"""
import array, csv, gzip, hashlib, io, ipaddress, json, os, socket, struct, sys, time, urllib.request

UA = "ip-reputation-builder (+https://github.com/Eliott-Markus/ip-reputation)"


def fetch(url):
    """Yields the body line by line (the proxy list has ~2.9 M lines); a cut download raises."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        length, got = r.headers.get("Content-Length"), 0
        for raw in r:
            got += len(raw)
            yield raw.decode("utf-8", "replace")
        if length and int(length) != got:   # a cut download must fail, not shrink the list
            raise IOError(f"short read {got}/{length}")


def whole(text_lines):
    return "".join(text_lines)


def lines(text_lines):
    for line in text_lines:
        line = line.split("#", 1)[0].strip()
        if line:
            yield line.split()[0].split(",")[0]


def tor_onionoo(text_lines):
    text = whole(text_lines)
    for relay in json.loads(text)["relays"]:
        for addr in relay.get("exit_addresses", []) + relay.get("or_addresses", []):
            addr = addr.rsplit(":", 1)[0] if addr.count(":") == 1 or addr.startswith("[") else addr
            yield addr.strip("[]")


def aws(text_lines):
    text = whole(text_lines)
    d = json.loads(text)
    yield from (p["ip_prefix"] for p in d["prefixes"])
    yield from (p["ipv6_prefix"] for p in d["ipv6_prefixes"])


def gcp(text_lines):
    text = whole(text_lines)
    for p in json.loads(text)["prefixes"]:
        yield p.get("ipv4Prefix") or p.get("ipv6Prefix")


def oracle(text_lines):
    text = whole(text_lines)
    for region in json.loads(text)["regions"]:
        yield from (c["cidr"] for c in region["cidrs"])


def first_column(text_lines):
    for row in csv.reader(text_lines):
        if row and not row[0].startswith("#"):
            yield row[0].strip()


SOURCES = {   # name: (url, parser, what it is)
    "tor_bulk_exits":    ("https://check.torproject.org/torbulkexitlist", lines, "Tor exit nodes (IPv4)"),
    "tor_relays":        ("https://onionoo.torproject.org/details?flag=Exit&running=true&fields=or_addresses,exit_addresses", tor_onionoo, "Tor exit relays (IPv4 + IPv6)"),
    "x4b_vpn_v4":        ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", lines, "VPN providers"),
    "x4b_vpn_v6":        ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt", lines, "VPN providers"),
    "x4b_datacenter_v4": ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt", lines, "Datacenter / hosting"),
    "x4b_datacenter_v6": ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt", lines, "Datacenter / hosting"),
    "firehol_level1":    ("https://iplists.firehol.org/files/firehol_level1.netset", lines, "FireHOL level 1 blocklist"),
    "firehol_proxies":   ("https://iplists.firehol.org/files/firehol_proxies.netset", lines, "FireHOL open / abusive proxies"),
    "aws":               ("https://ip-ranges.amazonaws.com/ip-ranges.json", aws, "Amazon Web Services"),
    "gcp":               ("https://www.gstatic.com/ipranges/cloud.json", gcp, "Google Cloud"),
    "oracle":            ("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", oracle, "Oracle Cloud"),
    "digitalocean":      ("https://digitalocean.com/geo/google.csv", first_column, "DigitalOcean"),
    "linode":            ("https://geoip.linode.com/", first_column, "Linode / Akamai"),
}
# residential addresses that must never be listed (French ISPs): a build listing one is broken
MUST_PASS = ["90.91.92.93", "82.64.231.243", "2a01:cb00::1"]


def merge(ranges):
    """IPv6: small, plain tuples."""
    out = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return out


def merge_v4(packed):
    """IPv4: millions of ranges kept packed (start << 32 | end) in an array, never as Python tuples."""
    packed = array.array("Q", sorted(packed))
    out = array.array("Q")
    cur_s = cur_e = None
    for x in packed:
        s, e = x >> 32, x & 0xFFFFFFFF
        if cur_s is not None and s <= cur_e + 1:
            cur_e = max(cur_e, e)
            continue
        if cur_s is not None:
            out.append(cur_s << 32 | cur_e)
        cur_s, cur_e = s, e
    if cur_s is not None:
        out.append(cur_s << 32 | cur_e)
    return out


def main():
    previous = {}
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        previous = {k: v["count"] for k, v in json.load(open(sys.argv[1])).get("sources", {}).items()}
    v4 = array.array("Q")   # start << 32 | end, 8 bytes per range
    v6, meta, errors = [], {}, []
    for name, (url, parse, label) in SOURCES.items():
        count = 0
        try:
            for item in parse(fetch(url)):
                ip, _, bits = item.partition("/")
                if ":" not in ip:   # IPv4 fast path, no ipaddress objects
                    try:
                        start = struct.unpack("!I", socket.inet_aton(ip))[0]
                    except OSError:
                        continue
                    size = 1 << (32 - int(bits or 32)) if (bits or "32").isdigit() and int(bits or 32) <= 32 else None
                    if size is None:
                        continue
                    start -= start % size
                    v4.append(start << 32 | (start + size - 1))
                else:
                    try:
                        net = ipaddress.ip_network(item, strict=False)
                    except ValueError:
                        continue
                    v6.append((int(net.network_address), int(net.broadcast_address)))
                count += 1
        except Exception as e:
            errors.append(f"{name}: download failed ({e})")
            continue
        if count < 0.5 * previous.get(name, 0) or count == 0:
            errors.append(f"{name}: {count} entries, previous build had {previous.get(name)}")
        meta[name] = {"url": url, "what": label, "count": count}
        print(f"{name:20} {count:>9}", flush=True)
    m4, m6 = merge_v4(v4), merge(v6)
    del v4
    for ip in MUST_PASS:
        n = int(ipaddress.ip_address(ip))
        rows = ((x >> 32, x & 0xFFFFFFFF) for x in m4) if ":" not in ip else m6
        if any(s <= n <= e for s, e in rows):
            errors.append(f"sanity: residential {ip} is listed")
    if errors:
        print("REFUSED:\n  " + "\n  ".join(errors), file=sys.stderr)
        sys.exit(1)
    os.makedirs("dist", exist_ok=True)
    files = {}
    for fname, rows, fmt in (("ipv4.txt.gz", ((x >> 32, x & 0xFFFFFFFF) for x in m4), "{} {}\n"),
                             ("ipv6.txt.gz", m6, "{:032x} {:032x}\n")):
        with gzip.GzipFile(f"dist/{fname}", "wb", mtime=0) as gz:   # streamed: no multi-MB string in memory
            n = 0
            for s, e in rows:
                gz.write(fmt.format(s, e).encode())
                n += 1
        data = open(f"dist/{fname}", "rb").read()
        files[fname] = {"ranges": n, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": files, "sources": meta},
              open("dist/meta.json", "w"), indent=1)
    print(f"ipv4 {len(m4)} ranges, ipv6 {len(m6)} ranges")


if __name__ == "__main__":
    main()
