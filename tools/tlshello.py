"""TLS key-exchange groups offered and selected on every new TCP connection of a packet capture.

Usage: python3 tlshello.py capture.pcap [--names names.txt] [--json out.json]

Reads a classic pcap file (tcpdump -w; link types Ethernet, Linux cooked v1 and v2, raw IPv4),
reassembles the first bytes of each direction of every IPv4 TCP connection whose SYN is in the
capture, and parses the TLS handshake records that open it:
  ClientHello  supported_groups and key_share groups offered
  ServerHello  key_share group selected, negotiated version (supported_versions), and whether the
               server first answered with a HelloRetryRequest
Connections that do not start with a TLS handshake (plain HTTP/2, chaincode traffic) are listed as
"not TLS". --names gives "IP name" lines (from docker network inspect) so that endpoints are named.
Dependency-free (standard library only).
"""
import json
import struct
import sys
from collections import defaultdict

GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001d: "X25519", 0x001e: "X448",
          0x0100: "ffdhe2048", 0x11eb: "SecP256r1MLKEM768", 0x11ec: "X25519MLKEM768", 0x11ed: "SecP384r1MLKEM1024",
          0x6399: "X25519Kyber768Draft00", 0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024"}
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
MAX_STREAM = 16384          # bytes per direction kept for parsing


def gname(g):
    return GROUPS.get(g, f"0x{g:04x}")


def read_pcap(path):
    """Yield (linktype, packet bytes) from a classic pcap file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        else:
            raise ValueError("not a classic pcap file (pcapng is not supported; use tcpdump -w)")
        linktype = struct.unpack(e + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _, _, incl, _ = struct.unpack(e + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield linktype, data


def ipv4_of(linktype, pkt):
    """Return the IPv4 packet inside a captured frame, or None."""
    if linktype == 1:                                   # Ethernet (with optional 802.1Q tags)
        off, et = 12, None
        while off + 2 <= len(pkt):
            et = struct.unpack(">H", pkt[off:off + 2])[0]
            if et in (0x8100, 0x88a8):
                off += 4
                continue
            off += 2
            break
        return pkt[off:] if et == 0x0800 else None
    if linktype == 113:                                 # Linux cooked v1: protocol at bytes 14-15
        return pkt[16:] if len(pkt) >= 16 and struct.unpack(">H", pkt[14:16])[0] == 0x0800 else None
    if linktype == 276:                                 # Linux cooked v2: protocol at bytes 0-1
        return pkt[20:] if len(pkt) >= 20 and struct.unpack(">H", pkt[0:2])[0] == 0x0800 else None
    if linktype in (101, 228):                          # raw IP / raw IPv4
        return pkt if pkt and pkt[0] >> 4 == 4 else None
    return None


def tcp_segments(path):
    """Yield (src, sport, dst, dport, seq, flags, payload) for every IPv4 TCP segment."""
    for lt, pkt in read_pcap(path):
        ip = ipv4_of(lt, pkt)
        if not ip or len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        if total and total < len(ip):
            ip = ip[:total]                             # drop link-layer padding; 0 = offloaded super-packet
        frag = struct.unpack(">H", ip[6:8])[0]
        if frag & 0x1FFF:
            continue                                    # a later fragment carries no TCP header
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        yield src, sport, dst, dport, seq, flags, tcp[doff:]


def streams(path):
    """Reassemble the first MAX_STREAM bytes of each direction of connections whose SYN was captured."""
    isn = {}                                            # (src, sport, dst, dport) -> initial sequence number
    segs = defaultdict(dict)                            # direction -> {relative offset: payload}
    for src, sport, dst, dport, seq, flags, payload in tcp_segments(path):
        k = (src, sport, dst, dport)
        if flags & 0x02:                                # SYN (and SYN-ACK): the first data byte is isn + 1
            isn.setdefault(k, seq)
            continue
        if k not in isn or not payload:
            continue
        off = (seq - isn[k] - 1) & 0xFFFFFFFF
        if off >= MAX_STREAM:
            continue
        if off not in segs[k] or len(payload) > len(segs[k][off]):
            segs[k][off] = payload
    out = {}
    for k in isn:
        buf, pos = bytearray(), 0
        for off in sorted(segs.get(k, {})):
            p = segs[k][off]
            if off > pos:
                break                                   # gap: keep the contiguous prefix only
            if off + len(p) > pos:
                buf += p[pos - off:]
                pos = off + len(p)
            if pos >= MAX_STREAM:
                break
        out[k] = bytes(buf[:MAX_STREAM])
    return out


def handshake_messages(stream):
    """Return [(type, body)] from the leading TLS handshake records of a stream, or None if not TLS."""
    i, hs = 0, bytearray()
    if len(stream) < 5 or stream[0] != 22 or stream[1] != 3:
        return None
    while i + 5 <= len(stream) and stream[i] in (20, 22):  # handshake records; skip ChangeCipherSpec
        ln = struct.unpack(">H", stream[i + 3:i + 5])[0]
        if stream[i] == 22:
            hs += stream[i + 5:i + 5 + ln]
        i += 5 + ln
    msgs, j = [], 0
    while j + 4 <= len(hs):
        t = hs[j]
        ln = int.from_bytes(hs[j + 1:j + 4], "big")
        if j + 4 + ln > len(hs):
            msgs.append((t, None))                      # truncated (capture or reassembly limit)
            break
        msgs.append((t, bytes(hs[j + 4:j + 4 + ln])))
        j += 4 + ln
    return msgs


def extensions(body, start):
    """Parse the extension block that starts at body[start]; return {type: data}."""
    ext = {}
    if start + 2 > len(body):
        return ext
    end = start + 2 + struct.unpack(">H", body[start:start + 2])[0]
    i = start + 2
    while i + 4 <= min(end, len(body)):
        et, ln = struct.unpack(">HH", body[i:i + 4])
        ext[et] = body[i + 4:i + 4 + ln]
        i += 4 + ln
    return ext


def parse_client_hello(b):
    i = 2 + 32                                          # legacy_version, random
    i += 1 + b[i]                                       # session id
    i += 2 + struct.unpack(">H", b[i:i + 2])[0]         # cipher suites
    i += 1 + b[i]                                       # compression methods
    ext = extensions(b, i)
    r = {"sni": None, "supported_groups": [], "key_share_groups": [], "key_share_bytes": {}}
    if 0 in ext and len(ext[0]) > 5:
        r["sni"] = ext[0][5:].decode("ascii", "replace")
    if 10 in ext:
        d = ext[10]
        r["supported_groups"] = [gname(struct.unpack(">H", d[k:k + 2])[0]) for k in range(2, 2 + struct.unpack(">H", d[:2])[0], 2)]
    if 51 in ext:
        d, k = ext[51], 2
        while k + 4 <= len(d):
            g, ln = struct.unpack(">HH", d[k:k + 4])
            r["key_share_groups"].append(gname(g))
            r["key_share_bytes"][gname(g)] = ln
            k += 4 + ln
    if 43 in ext:
        d = ext[43]
        r["versions"] = [f"0x{struct.unpack('>H', d[k:k + 2])[0]:04x}" for k in range(1, 1 + d[0], 2)]
    return r


def parse_server_hello(b):
    random = b[2:34]                                    # after legacy_version
    i = 34
    i += 1 + b[i]                                       # session id
    cipher = struct.unpack(">H", b[i:i + 2])[0]
    i += 2 + 1                                          # cipher suite, compression method
    ext = extensions(b, i)
    r = {"hello_retry_request": random == HRR_RANDOM, "cipher_suite": f"0x{cipher:04x}", "group": None, "key_share_bytes": None, "version": "0x0303"}
    if 43 in ext and len(ext[43]) == 2:
        r["version"] = f"0x{struct.unpack('>H', ext[43])[0]:04x}"
    if 51 in ext and len(ext[51]) >= 2:
        r["group"] = gname(struct.unpack(">H", ext[51][:2])[0])
        if len(ext[51]) >= 4 and not r["hello_retry_request"]:
            r["key_share_bytes"] = struct.unpack(">H", ext[51][2:4])[0]
    return r


def analyse(pcap, names=None):
    names = names or {}
    st = streams(pcap)
    conns = []
    for (src, sport, dst, dport), cstream in st.items():
        rev = (dst, dport, src, sport)
        if rev not in st:
            continue                                    # one direction only: no SYN-ACK seen
        # the client is the side that sent the first SYN; the SYN-ACK side also has an ISN, so keep the
        # direction whose first message is a ClientHello (or, for non-TLS, the lower port as server)
        msgs = handshake_messages(cstream)
        if not msgs or msgs[0][0] != 1:
            continue                                    # this direction is not the client of a TLS handshake
        c = {"client": names.get(src, src), "client_ip": src, "server": names.get(dst, dst), "server_ip": dst,
             "server_port": dport}
        if msgs[0][1] is None:
            c["error"] = "ClientHello truncated"
        else:
            try:
                c.update({"client_hello": parse_client_hello(msgs[0][1])})
            except Exception as e:  # noqa: BLE001
                c["error"] = f"ClientHello parse: {e}"
        smsgs = handshake_messages(st[rev]) or []
        sh = [m for m in smsgs if m[0] == 2]
        if sh and sh[0][1] is not None:
            try:
                first = parse_server_hello(sh[0][1])
                c["server_hello"] = first
                if first["hello_retry_request"]:
                    c["hrr_group"] = first["group"]
                    # after a HelloRetryRequest the real ServerHello follows in the same direction
                    later = [m for m in sh[1:] if m[1] is not None]
                    if later:
                        c["server_hello"] = parse_server_hello(later[0][1])
                c["selected_group"] = c["server_hello"]["group"]
            except Exception as e:  # noqa: BLE001
                c["error"] = f"ServerHello parse: {e}"
        else:
            c["selected_group"] = None
            c.setdefault("error", "no ServerHello in the capture")
        conns.append(c)
    conns.sort(key=lambda c: (c["client"], c["server"], c["server_port"]))
    summary = defaultdict(lambda: defaultdict(int))
    for c in conns:
        summary[f"{c['client']} -> {c['server']}:{c['server_port']}"][str(c.get("selected_group"))] += 1
    tcp_conns = sum(1 for k in st if (k[2], k[3], k[0], k[1]) in st) // 2
    return {"file": pcap, "tcp_connections_with_handshake_seen": tcp_conns, "tls_connections": len(conns),
            "by_endpoint_pair": {k: dict(v) for k, v in sorted(summary.items())}, "connections": conns}


def main(argv):
    out = names_file = None
    args = list(argv)
    if "--json" in args:
        out = args[args.index("--json") + 1]
        del args[args.index("--json"):args.index("--json") + 2]
    if "--names" in args:
        names_file = args[args.index("--names") + 1]
        del args[args.index("--names"):args.index("--names") + 2]
    names = {}
    if names_file:
        for line in open(names_file):
            p = line.split()
            if len(p) >= 2:
                names[p[0]] = p[1]
    res = analyse(args[0], names)
    for k, v in res["by_endpoint_pair"].items():
        print(f"{k}: {v}")
    print(f"TLS connections: {res['tls_connections']} (TCP connections with SYN and SYN-ACK: {res['tcp_connections_with_handshake_seen']})")
    if out:
        with open(out, "w") as f:
            json.dump(res, f, indent=1)
    return res


if __name__ == "__main__":
    main(sys.argv[1:])
