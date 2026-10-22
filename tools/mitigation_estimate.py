#!/usr/bin/env python3
"""Estimate how much smaller a Fabric block file would be if identities were stored more compactly.

Usage: python3 mitigation_estimate.py blockfile_000000 [more block files of the same ledger] --json out.json

Fabric stores every identity as a SerializedIdentity{1 mspid, 2 id_bytes}, where id_bytes is the
X.509 certificate as PEM text. Identities appear in each transaction (the client in the payload
header and again in the action header, and one per endorsement) and in the orderer signature of
every block's metadata. This tool rebuilds the block file with id_bytes replaced by

  der  the DER encoding of the same certificate (the base64 body of the PEM, decoded)
  ref  a 32-byte reference (SHA-256 of the DER certificate), as if identities already known to the
       channel were referred to instead of embedded

re-encoding every enclosing protobuf message and length prefix, and reports the size of the
result. Nothing else is changed: signatures, hashes and configuration blocks keep their sizes, and
the rebuilt files are counterfactual (their signatures would not verify). Rebuilding with the
certificates unchanged must reproduce the file byte for byte; the tool checks this. Bytes per
transaction are given without the configuration-only blocks (in every variant), and compression is
measured on the file without them.

It also measures general-purpose compression of the original file (gzip level 6 and xz preset 6
from the Python standard library, and zstd level 3 when the zstd command is installed), as a
storage layer with compression would see it.
"""
import base64
import gzip
import hashlib
import json
import lzma
import shutil
import subprocess
import sys


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; r |= (c & 0x7F) << s; i += 1
        if not c & 0x80:
            return r, i
        s += 7


def enc_varint(n):
    out = bytearray()
    while True:
        c = n & 0x7F; n >>= 7
        if n:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


def raw_fields(b):
    """Yield (field_no, wire_type, raw_bytes_of_whole_field, value_bytes_or_None)."""
    i, n = 0, len(b)
    while i < n:
        start = i; key, i = varint(b, i); f, wt = key >> 3, key & 7
        if wt == 0:
            _, i = varint(b, i); v = None
        elif wt == 2:
            ln, i = varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1:
            i += 8; v = None
        elif wt == 5:
            i += 4; v = None
        else:
            raise ValueError(f"wire type {wt}")
        if i > n:
            raise ValueError("truncated field")
        yield f, wt, b[start:i], v


# Schemas: field number -> schema of the embedded message, or "ID" for SerializedIdentity.id_bytes.
SERIALIZED_IDENTITY = {2: "ID"}
SIGNATURE_HEADER = {1: SERIALIZED_IDENTITY}
HEADER = {2: SIGNATURE_HEADER}
ENDORSEMENT = {1: SERIALIZED_IDENTITY}
ENDORSED_ACTION = {2: ENDORSEMENT}
CC_ACTION_PAYLOAD = {2: ENDORSED_ACTION}
TX_ACTION = {1: SIGNATURE_HEADER, 2: CC_ACTION_PAYLOAD}
TRANSACTION = {1: TX_ACTION}
PAYLOAD = {1: HEADER, 2: TRANSACTION}
ENVELOPE = {1: PAYLOAD}
METADATA_SIGNATURE = {1: SIGNATURE_HEADER}
METADATA = {2: METADATA_SIGNATURE}


class Rewriter:
    def __init__(self, mode):
        self.mode = mode; self.rewritten = 0; self.where = None; self.counts = {"transactions": 0, "block_metadata": 0}

    def ident(self, idb):
        if not idb.startswith(b"-----BEGIN"):
            return idb
        self.rewritten += 1; self.counts[self.where] += 1
        if self.mode == "pem":
            return idb
        lines = [l for l in idb.decode("ascii").splitlines() if l and not l.startswith("-----")]
        der = base64.b64decode("".join(lines))
        return der if self.mode == "der" else hashlib.sha256(der).digest()

    def msg(self, b, schema):
        out = bytearray()
        for f, wt, raw, v in raw_fields(b):
            sub = schema.get(f) if wt == 2 else None
            if sub is None:
                out += raw; continue
            nv = self.ident(v) if sub == "ID" else self.msg(v, sub)
            if nv is v or nv == v:
                out += raw
            else:
                out += enc_varint((f << 3) | 2) + enc_varint(len(nv)) + nv
        return bytes(out)


def is_endorser_tx(env):
    for f, wt, raw, payload in raw_fields(env):
        if f == 1 and wt == 2:
            for pf, pwt, praw, header in raw_fields(payload):
                if pf == 1 and pwt == 2:
                    for hf, hwt, hraw, chdr in raw_fields(header):
                        if hf == 1 and hwt == 2:
                            for cf, cwt, craw, cv in raw_fields(chdr):
                                if cf == 1 and cwt == 0:
                                    return varint(craw, 1)[0] == 3
    return False


def rebuild(data, rw):
    """Rebuild a whole block file. Returns (bytes, endorser transactions, blocks, bytes of the
    configuration-only blocks in the result, original records of the other blocks)."""
    out = bytearray(); i = 0; ntx_total = 0; nblk = 0; cfg_bytes = 0; data_records = bytearray()
    while i < len(data):
        rec_start = i
        ln, j = varint(data, i); blk = data[j:j + ln]; i = j + ln; nblk += 1; block_endorser = 0
        k = 0; nb = bytearray()
        _, k2 = varint(blk, k); nb += blk[k:k2]; k = k2                      # block number
        for _ in range(2):                                                   # DataHash, PreviousHash
            h, k2 = varint(blk, k); nb += blk[k:k2 + h]; k = k2 + h
        ntx, k2 = varint(blk, k); nb += blk[k:k2]; k = k2
        for _ in range(ntx):
            el, k2 = varint(blk, k); env = blk[k2:k2 + el]; k = k2 + el
            if is_endorser_tx(env):
                ntx_total += 1; block_endorser += 1; rw.where = "transactions"; env = rw.msg(env, ENVELOPE)
            nb += enc_varint(len(env)) + env
        nmeta, k2 = varint(blk, k); nb += blk[k:k2]; k = k2
        for m in range(nmeta):
            el, k2 = varint(blk, k); item = blk[k2:k2 + el]; k = k2 + el
            if m == 0 and item:                                              # SIGNATURES metadata
                rw.where = "block_metadata"; item = rw.msg(item, METADATA)
            nb += enc_varint(len(item)) + item
        assert k == len(blk), "block not fully consumed"
        rec = enc_varint(len(nb)) + nb
        out += rec
        if block_endorser == 0:
            cfg_bytes += len(rec)
        else:
            data_records += data[rec_start:i]
    return bytes(out), ntx_total, nblk, cfg_bytes, bytes(data_records)


def main(paths, out_json):
    data = b"".join(open(p, "rb").read() for p in paths)
    res = {"files": paths, "file_bytes": len(data)}
    same, ntx, nblk, cfg, records = rebuild(data, Rewriter("pem"))
    assert same == data, "rebuilding with unchanged identities did not reproduce the file"
    assert len(records) + cfg == len(data)
    # Bytes per transaction leave out the configuration-only blocks (genesis and channel updates), in every
    # variant; "with_config_per_tx" keeps them, as in a whole-file average.
    base = len(data) - cfg
    res.update(transactions=ntx, blocks=nblk, config_block_bytes=cfg,
               identity_check="rebuild reproduces the file byte for byte")
    res["pem"] = {"file_bytes": base, "per_tx": base / ntx, "with_config_per_tx": len(data) / ntx}
    for mode in ("der", "ref"):
        rw = Rewriter(mode)
        b, _, _, cfg2, _ = rebuild(data, rw)
        nb = len(b) - cfg2
        res[mode] = {"file_bytes": nb, "per_tx": nb / ntx, "saving_pct": 100 * (1 - nb / base),
                     "identities_rewritten": rw.counts,
                     "identities_per_tx": rw.counts["transactions"] / ntx}
    comp = {"gzip6": len(gzip.compress(records, 6)), "xz6": len(lzma.compress(records, preset=6))}
    if shutil.which("zstd"):
        comp["zstd3"] = len(subprocess.run(["zstd", "-3", "-c", "-q"], input=records, capture_output=True, check=True).stdout)
    for k, v in comp.items():
        res[k] = {"file_bytes": v, "per_tx": v / ntx, "saving_pct": 100 * (1 - v / base)}
    json.dump(res, open(out_json, "w"), indent=1)
    print(f"{ntx} transactions in {nblk} blocks, {len(data)} B; without configuration blocks {base / ntx:.0f} B/tx")
    for k in ("der", "ref", "gzip6", "xz6", "zstd3"):
        if k in res:
            print(f"  {k:6s} {res[k]['per_tx']:9.0f} B/tx  saving {res[k]['saving_pct']:5.1f}%")


if __name__ == "__main__":
    a = sys.argv[1:]
    if "--json" not in a or a.index("--json") == len(a) - 1:
        sys.exit(__doc__)
    out = a[a.index("--json") + 1]
    main([x for x in a if x not in ("--json", out)], out)
