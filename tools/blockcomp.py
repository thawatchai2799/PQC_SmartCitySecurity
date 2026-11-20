"""Compression of a Fabric peer block file one block at a time, with and without a dictionary.

Usage: python3 blockcomp.py blockfile_000000 [more block files of the same ledger]
                            --certs cert1.pem [cert2.pem ...] [--json out.json]

The peer stores each block as [varint length][serialized block]. A block is the unit a peer reads
back during validation, state recovery and block delivery, so this tool compresses every block on
its own (configuration-only blocks are left out, as in the whole-file estimate of the paper):
  gzip6        gzip level 6 (Python standard library), per block
  zstd3        zstd level 3, per block, no dictionary
  zstd3_certs  zstd level 3, per block, with a raw-content dictionary made of the PEM certificates
               given with --certs (the identities that every transaction repeats); every block is
               decompressed again and compared with the original
  zstd3_trained  zstd level 3 with a dictionary trained (zstd --train) on the first half of the
               transaction blocks, measured on the second half only, next to zstd3 on the same half
It also reports the whole-file zstd 3 of the same transaction blocks for reference, and how often
each certificate occurs in them. Requires the zstd command.
"""
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]
        r |= (c & 0x7F) << s
        i += 1
        if not c & 0x80:
            return r, i
        s += 7


def fields(b):
    i, n = 0, len(b)
    while i < n:
        key, i = varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            ln, i = varint(b, i)
            v = b[i:i + ln]
            i += ln
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        else:
            raise ValueError(f"wire type {wt}")
        yield f, wt, v


def endorser_txs(blk):
    """Number of ENDORSER_TRANSACTION envelopes in a serialized block (Fabric block_serialization.go)."""
    i = 0
    _, i = varint(blk, i)                               # block number
    ln, i = varint(blk, i)
    i += ln                                             # data hash
    ln, i = varint(blk, i)
    i += ln                                             # previous hash
    ntx, i = varint(blk, i)
    n = 0
    for _ in range(ntx):
        ln, i = varint(blk, i)
        env = blk[i:i + ln]
        i += ln
        for f, wt, payload in fields(env):
            if f == 1 and wt == 2:
                for pf, pwt, hdr in fields(payload):
                    if pf == 1 and pwt == 2:
                        for hf, hwt, ch in fields(hdr):
                            if hf == 1 and hwt == 2:
                                for cf, cwt, cv in fields(ch):
                                    if cf == 1 and cwt == 0 and cv == 3:
                                        n += 1
    return n


def blocks_of(paths):
    out = []
    for p in paths:
        b = open(p, "rb").read()
        i = 0
        while i < len(b):
            ln, j = varint(b, i)
            out.append(b[j:j + ln])
            i = j + ln
    return out


def zstd(data, *extra):
    return subprocess.run(["zstd", "-3", "-c", "-q", *extra], input=data, capture_output=True, check=True).stdout


def unzstd(data, *extra):
    return subprocess.run(["zstd", "-d", "-c", "-q", *extra], input=data, capture_output=True, check=True).stdout


def main(argv):
    args = list(argv)
    out = None
    if "--json" in args:
        out = args[args.index("--json") + 1]
        del args[args.index("--json"):args.index("--json") + 2]
    certs = []
    if "--certs" in args:
        k = args.index("--certs")
        certs = args[k + 1:]
        args = args[:k]
    files = args
    if not shutil.which("zstd"):
        raise SystemExit("the zstd command is required")
    blocks = blocks_of(files)
    txb = [(b, endorser_txs(b)) for b in blocks]
    txb = [(b, n) for b, n in txb if n > 0]
    ntx = sum(n for _, n in txb)
    if not txb:
        raise SystemExit("no transaction blocks")
    raw = sum(len(b) for b, _ in txb)
    res = {"files": [os.path.basename(f) for f in files], "blocks_total": len(blocks), "transaction_blocks": len(txb),
           "transactions": ntx, "raw_bytes": raw, "zstd_version": subprocess.run(["zstd", "-V"], capture_output=True, text=True).stdout.strip()}

    # certificate dictionary (raw content: the PEM files as they appear in the identities)
    pems, seen = [], set()
    for c in certs:
        d = open(c, "rb").read()
        h = hashlib.sha256(d).hexdigest()
        if h not in seen:
            seen.add(h)
            pems.append((os.path.basename(c), d))
    allraw = b"".join(b for b, _ in txb)
    res["certificates"] = [{"file": n, "bytes": len(d), "occurrences_in_transaction_blocks": allraw.count(d)} for n, d in pems]
    tmp = tempfile.mkdtemp(prefix="blockcomp-")
    try:
        dict_path = os.path.join(tmp, "certs.dict")
        with open(dict_path, "wb") as f:
            f.write(b"".join(d for _, d in pems))
        res["cert_dictionary_bytes"] = os.path.getsize(dict_path)

        g = z = zd = 0
        for b, _ in txb:
            g += len(gzip.compress(b, 6))
            z += len(zstd(b))
            if pems:
                c = zstd(b, "-D", dict_path)
                if unzstd(c, "-D", dict_path) != b:
                    raise SystemExit("round trip with the certificate dictionary failed")
                zd += len(c)
        per = {"gzip6": g, "zstd3": z}
        if pems:
            per["zstd3_certs"] = zd
        res["per_block"] = {k: {"bytes": v, "saving_pct": round(100 * (1 - v / raw), 1), "bytes_per_tx": round(v / ntx, 1)} for k, v in per.items()}
        res["raw_bytes_per_tx"] = round(raw / ntx, 1)
        whole = len(zstd(allraw))
        res["whole_file_zstd3"] = {"bytes": whole, "saving_pct": round(100 * (1 - whole / raw), 1), "bytes_per_tx": round(whole / ntx, 1)}

        # trained dictionary: train on the first half of the transaction blocks, measure on the second half
        half = len(txb) // 2
        train, test = txb[:half], txb[half:]
        tr = {"train_blocks": len(train), "test_blocks": len(test)}
        if len(train) >= 8:
            sdir = os.path.join(tmp, "samples")
            os.mkdir(sdir)
            for k, (b, _) in enumerate(train):
                with open(os.path.join(sdir, f"b{k:05d}"), "wb") as f:
                    f.write(b)
            tdict = os.path.join(tmp, "trained.dict")
            p = subprocess.run(["zstd", "--train", "-q", "-o", tdict] + [os.path.join(sdir, x) for x in sorted(os.listdir(sdir))],
                               capture_output=True, text=True)
            if p.returncode == 0 and os.path.exists(tdict):
                traw = sum(len(b) for b, _ in test)
                tz = tzd = 0
                for b, _ in test:
                    tz += len(zstd(b))
                    c = zstd(b, "-D", tdict)
                    if unzstd(c, "-D", tdict) != b:
                        raise SystemExit("round trip with the trained dictionary failed")
                    tzd += len(c)
                tr.update({"dictionary_bytes": os.path.getsize(tdict), "test_raw_bytes": traw,
                           "zstd3_bytes": tz, "zstd3_saving_pct": round(100 * (1 - tz / traw), 1),
                           "zstd3_trained_bytes": tzd, "zstd3_trained_saving_pct": round(100 * (1 - tzd / traw), 1)})
            else:
                tr["error"] = (p.stderr or p.stdout).strip()[-400:]
        else:
            tr["error"] = "too few transaction blocks to train a dictionary"
        res["trained_dictionary"] = tr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps(res, indent=1))
    if out:
        with open(out, "w") as f:
            json.dump(res, f, indent=1)
    return res


if __name__ == "__main__":
    main(sys.argv[1:])
