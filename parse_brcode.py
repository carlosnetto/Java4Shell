#!/usr/bin/env python3
"""
Pix BR Code (EMVCo TLV) parser — extracts the dynamic-Pix payload URL.

EMV format: each field is  ID(2) + LEN(2 decimal) + VALUE(LEN chars).
Some fields are templates whose VALUE is itself a sequence of sub-fields
(e.g. 26-51 Merchant Account Information, 62 Additional Data, 64 Language).

For a DYNAMIC Pix QR, the URL lives under the Merchant Account Information
template (commonly ID 26) whose sub-field 00 == "br.gov.bcb.pix" and whose
sub-field 25 holds the URL (no scheme — prepend https://).

Usage:
  python3 parse_brcode.py "000201...6304A827"      # full parse + URL
  python3 parse_brcode.py --url-only "000201..."    # just the https URL
  python3 parse_brcode.py --file qr.txt             # read payload from a file

Pipe into the exposure checker (dynamic Pix payloads re-sign themselves, so use
--samples to take a stable baseline; read the verdict as Y/N/?):
  python3 parse_brcode.py --url-only "000201..." | xargs -I{} python3 java4shell_check.py {} --samples 5
"""

import sys

PIX_GUI = "br.gov.bcb.pix"
# IDs whose value is a nested TLV sequence.
TEMPLATE_IDS = set(range(26, 52)) | {62, 64, 80, 81, 82}

FIELD_NAMES = {
    "00": "Payload Format Indicator",
    "01": "Point of Initiation Method",
    "52": "Merchant Category Code",
    "53": "Transaction Currency",
    "54": "Transaction Amount",
    "58": "Country Code",
    "59": "Merchant Name",
    "60": "Merchant City",
    "61": "Postal Code",
    "62": "Additional Data Field Template",
    "63": "CRC16",
}

# Names for sub-fields inside templates (context differs from top level).
SUBFIELD_NAMES = {
    "00": "GUI",
    "01": "Key / Reference",
    "02": "Payment description",
    "05": "Reference Label",
    "25": "URL",
}


def parse_tlv(s):
    """Return list of (id, value) at this level. Raises ValueError on bad length."""
    out = []
    i = 0
    n = len(s)
    while i < n:
        if i + 4 > n:
            raise ValueError(f"truncated field header at offset {i}: {s[i:]!r}")
        fid = s[i:i + 2]
        ln_str = s[i + 2:i + 4]
        if not ln_str.isdigit():
            raise ValueError(f"non-numeric length {ln_str!r} for id {fid} at offset {i}")
        ln = int(ln_str)
        val = s[i + 4:i + 4 + ln]
        if len(val) != ln:
            raise ValueError(f"id {fid} declares len {ln} but only {len(val)} chars remain")
        out.append((fid, val))
        i += 4 + ln
    return out


def crc16_ccitt_false(data: str) -> str:
    """CRC-16/CCITT-FALSE over ASCII bytes; poly 0x1021, init 0xFFFF."""
    crc = 0xFFFF
    for b in data.encode("ascii"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def find_pix_url(fields):
    """Walk Merchant Account Information templates; return the Pix URL or None."""
    for fid, val in fields:
        if fid.isdigit() and 26 <= int(fid) <= 51:
            try:
                subs = dict(parse_tlv(val))
            except ValueError:
                continue
            if subs.get("00") == PIX_GUI and subs.get("25"):
                return subs["25"]
    return None


def verify_crc(payload):
    """Return (ok, expected, found) for the trailing 6304XXXX field."""
    idx = payload.rfind("6304")
    if idx == -1 or idx + 8 > len(payload):
        return (None, None, None)
    found = payload[idx + 4:idx + 8]
    expected = crc16_ccitt_false(payload[:idx + 4])
    return (found.upper() == expected, expected, found.upper())


def pretty(fields, indent=0):
    lines = []
    for fid, val in fields:
        name = (FIELD_NAMES if indent == 0 else SUBFIELD_NAMES).get(fid, "")
        label = f"{'  ' * indent}{fid} {name}".rstrip()
        if fid.isdigit() and int(fid) in TEMPLATE_IDS:
            try:
                subs = parse_tlv(val)
                lines.append(f"{label}:")
                lines.extend(pretty(subs, indent + 1))
                continue
            except ValueError:
                pass
        lines.append(f"{label}: {val}")
    return lines


def main():
    args = sys.argv[1:]
    url_only = "--url-only" in args
    args = [a for a in args if a != "--url-only"]
    if args and args[0] == "--file":
        payload = open(args[1]).read().strip()
    elif args:
        payload = args[0].strip()
    else:
        print(__doc__)
        sys.exit(0)

    try:
        fields = parse_tlv(payload)
    except ValueError as e:
        print(f"PARSE ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    url = find_pix_url(fields)
    full_url = ("https://" + url) if url and "://" not in url else url

    if url_only:
        if full_url:
            print(full_url)
            sys.exit(0)
        print("", file=sys.stderr)
        sys.exit(1)

    print("Parsed BR Code:")
    for line in pretty(fields):
        print("  " + line)

    ok, expected, found = verify_crc(payload)
    print()
    if ok is None:
        print("CRC16     : (no 6304 field found)")
    else:
        print(f"CRC16     : found {found}, expected {expected} -> "
              f"{'VALID' if ok else 'MISMATCH'}")

    print()
    if full_url:
        print(f"Dynamic Pix URL : {full_url}")
        print(f"Next: python3 java4shell_check.py {full_url} --samples 5")
        print("      (--samples takes a baseline since the payload re-signs each "
              "call. Only Y is conclusive = token provably parsed; UNKNOWN proves "
              "nothing -- a silent decode looks identical. Patch in-range JDKs "
              "regardless; confirm with --local + check_classpath.py.)")
    else:
        print("Dynamic Pix URL : (none found — this may be a STATIC Pix QR, "
              "which carries a key/amount inline and has no callback URL)")


if __name__ == "__main__":
    main()
