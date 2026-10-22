#!/usr/bin/env python3
"""Per-block transaction counts and sizes of Hyperledger Fabric peer block files.

Usage: python3 block_sizes.py blockfile_000000 [blockfile_000001 ...] --json out.json

The peer stores each block as [varint length][serialized block] (see decode_blockfile.py for the
layout). For every block this tool records its number, the number of envelopes it holds, how many of
them are configuration envelopes, and its size in bytes. The output is
  {"files": [...], "blocks": [[number, envelopes, config_envelopes, bytes], ...]}
sorted by block number. A benchmark that ran between heights h0 and h1 (as reported by
`peer channel getinfo`) wrote the blocks numbered h0 .. h1-1.
"""
import json
import sys


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; r |= (c & 0x7F) << s; i += 1
        if not c & 0x80:
            return r, i
        s += 7


def fields(b):
    i, n = 0, len(b)
    while i < n:
        key, i = varint(b, i); f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            ln, i = varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1:
            v = b[i:i + 8]; i += 8
        elif wt == 5:
            v = b[i:i + 4]; i += 4
        else:
            raise ValueError(f"wire type {wt}")
        yield f, wt, v


def is_config(env):
    """True unless ChannelHeader.type is 3 (ENDORSER_TRANSACTION)."""
    for f, wt, payload in fields(env):
        if f == 1 and wt == 2:
            for pf, pwt, header in fields(payload):
                if pf == 1 and pwt == 2:
                    for hf, hwt, chdr in fields(header):
                        if hf == 1 and hwt == 2:
                            for cf, cwt, cv in fields(chdr):
                                if cf == 1 and cwt == 0:
                                    return cv != 3
    return True


def blocks_of(path):
    b = open(path, "rb").read(); i = 0
    while i < len(b):
        ln, j = varint(b, i); blk = b[j:j + ln]; i = j + ln
        k = 0
        number, k = varint(blk, k)
        h, k = varint(blk, k); k += h                 # DataHash
        h, k = varint(blk, k); k += h                 # PreviousHash
        ntx, k = varint(blk, k); ncfg = 0
        for _ in range(ntx):
            el, k = varint(blk, k); ncfg += is_config(blk[k:k + el]); k += el
        yield [number, ntx, ncfg, len(blk)]


def main(paths, out):
    rows = sorted((r for p in paths for r in blocks_of(p)), key=lambda r: r[0])
    nums = [r[0] for r in rows]
    gaps = [n for a, n in zip(nums, nums[1:]) if n != a + 1]
    res = {"files": paths, "blocks": rows, "first": nums[0] if nums else None,
           "last": nums[-1] if nums else None, "gaps": gaps}
    json.dump(res, open(out, "w"))
    print(f"{len(rows)} blocks ({res['first']}..{res['last']}), {sum(r[1] - r[2] for r in rows)} endorser "
          f"transactions, {sum(r[2] for r in rows)} config envelopes, gaps: {gaps or 'none'}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if "--json" not in a or a.index("--json") == len(a) - 1:
        sys.exit(__doc__)
    out = a[a.index("--json") + 1]
    main([x for x in a if x not in ("--json", out)], out)
