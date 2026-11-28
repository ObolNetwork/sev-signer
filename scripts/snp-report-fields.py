#!/usr/bin/env python3
"""Prints the fields of an SEV-SNP attestation report that the hardware
runbook records: measurement, policy, the four TCB values (raw 64-bit, the
form `dvtee sealing-key --snp-min-tcb` and SNP_MIN_TCB take), chip ID,
and the firmware version.

    scripts/snp-report-fields.py evidence.json   # from /api/v1/tee/attestation
    scripts/snp-report-fields.py report.bin      # raw 1184-byte report
    scripts/snp-report-fields.py --committed-tcb evidence.json   # just that value
    scripts/snp-report-fields.py --min-tcb evidence.json   # the SNP_MIN_TCB to pin

Offsets are from the SEV-SNP ABI (ATTESTATION_REPORT), as parsed by the
virtee `sev` crate. Nothing here checks the signature: that is
`dvtee verify-evidence` and `snpguest verify attestation`.
"""
import json
import struct
import sys

REPORT_LEN = 0x4A0

FIELDS_U32 = {"version": 0x00, "guest_svn": 0x04, "vmpl": 0x30, "signature_algo": 0x34}
FIELDS_U64 = {
    "policy": 0x08,
    "current_tcb": 0x38,
    "platform_info": 0x40,
    "reported_tcb": 0x180,
    "committed_tcb": 0x1E0,
    "launch_tcb": 0x1F0,
}
FIELDS_HEX = {
    "report_data": (0x50, 64),
    "measurement": (0x90, 48),
    "host_data": (0xC0, 32),
    "id_key_digest": (0xE0, 48),
    "chip_id": (0x1A0, 64),
}


def load(path):
    data = open(path, "rb").read()
    if data[:1] in (b"{", b" ", b"\n"):
        ev = json.loads(data)
        provider = ev.get("provider", "")
        if provider not in ("sev_guest", "insecure_dev"):
            sys.exit(f"provider {provider!r} is not an SEV-SNP report")
        data = bytes.fromhex(ev["report"].removeprefix("0x"))
    if len(data) < REPORT_LEN:
        sys.exit(f"report is {len(data)} bytes, want {REPORT_LEN}")
    return data


def fields(r):
    out = {}
    for k, off in FIELDS_U32.items():
        out[k] = struct.unpack_from("<I", r, off)[0]
    for k, off in FIELDS_U64.items():
        out[k] = "0x%016x" % struct.unpack_from("<Q", r, off)[0]
    for k, (off, n) in FIELDS_HEX.items():
        out[k] = r[off : off + n].hex()
    cur = r[0x1E8:0x1EB]
    com = r[0x1EC:0x1EF]
    out["firmware_current"] = f"{cur[2]}.{cur[1]}.{cur[0]}"
    out["firmware_committed"] = f"{com[2]}.{com[1]}.{com[0]}"
    pol = struct.unpack_from("<Q", r, 0x08)[0]
    out["policy_debug"] = bool(pol >> 19 & 1)
    out["policy_smt"] = bool(pol >> 16 & 1)
    out["policy_migrate_ma"] = bool(pol >> 18 & 1)
    return out


def min_tcb(r):
    """Component-wise minimum of REPORTED_TCB and COMMITTED_TCB.

    The minimum TCB a guest pins must not exceed either: verify-evidence
    --min-tcb checks both. They differ when firmware was loaded but not
    committed (the reported TCB then lags). Every component is one byte in
    both the Milan/Genoa and Turin layouts, and reserved bytes are zero, so a
    byte-wise minimum is a component-wise minimum.
    """
    rep = r[0x180:0x188]
    com = r[0x1E0:0x1E8]
    return "0x%016x" % int.from_bytes(bytes(min(a, b) for a, b in zip(rep, com)), "little")


def main(argv):
    if len(argv) == 3 and argv[1] == "--committed-tcb":
        print(fields(load(argv[2]))["committed_tcb"])
    elif len(argv) == 3 and argv[1] == "--min-tcb":
        print(min_tcb(load(argv[2])))
    elif len(argv) == 3 and argv[1] == "--json":
        print(json.dumps(fields(load(argv[2])), indent=2))
    elif len(argv) == 2 and not argv[1].startswith("-"):
        for k, v in fields(load(argv[1])).items():
            print(f"{k + ':':22} {v}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
