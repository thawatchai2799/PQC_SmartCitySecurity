"""Byte composition of a Hyperledger Fabric peer block file.

Reads a Fabric peer block file (ledgersData/chains/chains/<channel>/blockfile_000000).
The peer stores each block as [varint length][serialized block], where the serialized
block is fabric's own layout (common/ledger/blkstorage/block_serialization.go):
  varint header.Number | len+DataHash | len+PreviousHash | varint tx count |
  (len+Envelope bytes) x tx count | varint metadata count | (len+metadata item) x count
A dependency-free protobuf wire parser then attributes every byte to one of:

  block header            Block.header hashes (previous hash, data hash; the block-number varint is counted as framing)
  block metadata          Block.metadata (orderer/validator signatures, tx validity flags)
  envelope signature      Envelope.signature (the client's signature over the payload)
  payload header          Payload.header: channel header + signature header (creator cert)
  proposal payload        ChaincodeActionPayload.chaincode_proposal_payload
                          (chaincode name, function and arguments = the alert itself)
  read/write set          ChaincodeAction.results (TxReadWriteSet)
  response / events       ChaincodeAction.response + events + chaincode_id (here: no events; the
                          response carries a second copy of the stored JSON alert)
  endorsements            Endorsement.endorser (cert) + Endorsement.signature, per endorser
  framing                 protobuf tags/lengths and the file's length prefixes

Field numbers follow fabric-protos (common/common.proto, peer/transaction.proto,
peer/proposal.proto, peer/proposal_response.proto):
  Block{1 header, 2 data, 3 metadata}; BlockData{1 data: Envelope[]}; BlockMetadata{1 metadata[]}
  Envelope{1 payload, 2 signature}; Payload{1 header{1 channel_header, 2 signature_header}, 2 data}
  ChannelHeader{1 type, ...}; Transaction{1 actions[]}; TransactionAction{1 header, 2 payload}
  ChaincodeActionPayload{1 chaincode_proposal_payload, 2 action}
  ChaincodeEndorsedAction{1 proposal_response_payload, 2 endorsements[]}
  ProposalResponsePayload{1 proposal_hash, 2 extension=ChaincodeAction}
  ChaincodeAction{1 results, 2 events, 3 response, 4 chaincode_id}; Endorsement{1 endorser, 2 signature}

Usage: python decode_blockfile.py blockfile_000000 [--json out.json]
"""
import sys, json, collections


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; r |= (c & 0x7F) << s; i += 1
        if not c & 0x80: return r, i
        s += 7


def fields(b):
    """Yield (field_no, wire_type, value_bytes_or_int, total_bytes_of_this_field)."""
    i, n = 0, len(b)
    while i < n:
        start = i; key, i = varint(b, i); f, wt = key >> 3, key & 7
        if wt == 0: v, i = varint(b, i)
        elif wt == 2: ln, i = varint(b, i); v = b[i:i + ln]; i += ln
        elif wt == 1: v = b[i:i + 8]; i += 8
        elif wt == 5: v = b[i:i + 4]; i += 4
        else: raise ValueError(f"wire type {wt}")
        yield f, wt, v, i - start


def sub(b, no):
    return [v for f, wt, v, _ in fields(b) if f == no and wt == 2]


def header_type(payload_header):
    """ChannelHeader.type (1 = CONFIG, 3 = ENDORSER_TRANSACTION) from Payload.header."""
    for f, wt, v, _ in fields(payload_header):
        if f == 1:
            for cf, cwt, cv, _ in fields(v):
                if cf == 1 and cwt == 0: return cv
    return None


def decode_envelope(env, acc):
    payload = sub(env, 1)[0]
    htype = header_type(sub(payload, 1)[0])
    if htype != 3:                                   # config / genesis envelope: count whole, do not dissect
        acc["config_tx"] += 1; acc["config_envelope_bytes"] += len(env); return
    acc["tx"] += 1
    for ef, ewt, ev, _ in fields(env):
        if ef == 2: acc["envelope_signature"] += len(ev)
        elif ef == 1:
            for pf, pwt, pv, _ in fields(ev):
                if pf == 1: acc["payload_header"] += len(pv)
                elif pf == 2:                     # Transaction
                    for action in sub(pv, 1):
                        for af, awt, av, _ in fields(action):
                            if af == 1: acc["action_header"] += len(av)
                            elif af == 2:          # ChaincodeActionPayload
                                for cf, cwt, cv, _ in fields(av):
                                    if cf == 1: acc["proposal_payload"] += len(cv)
                                    elif cf == 2:  # ChaincodeEndorsedAction
                                        for xf, xwt, xv, _ in fields(cv):
                                            if xf == 1:    # ProposalResponsePayload
                                                for rf, rwt, rv, _ in fields(xv):
                                                    if rf == 1: acc["proposal_hash"] += len(rv)
                                                    elif rf == 2:   # ChaincodeAction
                                                        for gf, gwt, gv, _ in fields(rv):
                                                            if gf == 1: acc["rwset"] += len(gv)
                                                            else: acc["response_events_ccid"] += len(gv)
                                            elif xf == 2:  # Endorsement
                                                acc["endorsements"] += 1
                                                for nf, nwt, nv, _ in fields(xv):
                                                    if nf == 1: acc["endorser_cert"] += len(nv)
                                                    elif nf == 2: acc["endorser_signature"] += len(nv)


def decode_block(blk, acc):
    """fabric's serialized block layout (see module docstring)."""
    acc["block_bytes"] += len(blk); i = 0
    number, i = varint(blk, i)
    ln, i = varint(blk, i); i += ln; dh = ln                  # DataHash
    ln, i = varint(blk, i); i += ln; ph = ln                  # PreviousHash
    acc["block_header"] += dh + ph
    ntx, i = varint(blk, i)
    for _ in range(ntx):
        ln, i = varint(blk, i); decode_envelope(blk[i:i + ln], acc); i += ln
    nmeta, i = varint(blk, i)                                 # BlockMetadata: count, then len+item each
    for _ in range(nmeta):
        ln, i = varint(blk, i); acc["block_metadata"] += ln; i += ln
    assert i == len(blk), (i, len(blk))
    acc["last_block_number"] = number


def main(path, out=None):
    b = open(path, "rb").read(); i = 0; acc = collections.Counter(); blocks = 0; prefix = 0
    while i < len(b):
        ln, j = varint(b, i); prefix += j - i; blk = b[j:j + ln]; i = j + ln
        decode_block(blk, acc); blocks += 1
    cats = ["config_envelope_bytes", "block_header", "block_metadata", "envelope_signature", "payload_header", "action_header", "proposal_payload",
            "proposal_hash", "rwset", "response_events_ccid", "endorser_cert", "endorser_signature"]
    attributed = sum(acc[c] for c in cats)
    framing = acc["block_bytes"] - attributed
    res = dict(file=path, file_bytes=len(b), blocks=blocks, last_block_number=acc["last_block_number"],
               transactions=acc["tx"], config_transactions=acc["config_tx"], endorsements=acc["endorsements"],
               length_prefix_bytes=prefix, block_bytes=acc["block_bytes"], framing_bytes=framing,
               bytes={c: acc[c] for c in cats},
               share={c: round(100 * acc[c] / len(b), 2) for c in cats},
               per_tx_bytes={c: round(acc[c] / max(acc["tx"], 1), 1) for c in cats},
               file_bytes_per_tx=round(len(b) / max(acc["tx"], 1), 1))
    res["share"]["framing"] = round(100 * (framing + prefix) / len(b), 2)
    print(json.dumps(res, indent=1))
    if out: json.dump(res, open(out, "w"), indent=1)
    return res


if __name__ == "__main__":
    args = sys.argv[1:]; out = None
    if "--json" in args: out = args[args.index("--json") + 1]; args = [a for a in args if a not in ("--json", out)]
    main(args[0], out)
