#!/usr/bin/env python3
"""
Java4Shell (CVE-2026-114938) — batch reachability sweep. DEFENSIVE / non-destructive.

Reads a list of URLs (one per line, '#' comments allowed) and prints a Y/N
table of whether each endpoint parses an Authorization: Bearer token.
Sends only harmless, well-formed Base64 — never the exploit payload.

Usage:
  python3 sweep.py endpoints.txt
  python3 sweep.py endpoints.txt --csv results.csv
"""

import sys
import ssl
import csv
import base64
import urllib.request
import urllib.error

BENIGN_BEARER = base64.b64encode(b"not-a-real-token").decode()
TIMEOUT = 10


def _get(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.status, r.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(4096) if e.fp else b"")
    except Exception as e:
        return None, str(e).encode()


def probe(url):
    b_status, b_body = _get(url, {"User-Agent": "j4s-sweep"})
    if b_status is None:
        return "ERR", b_status, None, b_body.decode(errors="replace")[:80]
    t_status, t_body = _get(
        url, {"User-Agent": "j4s-sweep", "Authorization": f"Bearer {BENIGN_BEARER}"}
    )
    changed = (t_status != b_status) or (t_body != b_body)
    return ("Y" if changed else "N"), b_status, t_status, ""


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    path = sys.argv[1]
    csv_out = None
    if "--csv" in sys.argv:
        csv_out = sys.argv[sys.argv.index("--csv") + 1]

    with open(path) as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    rows = []
    print(f"{'REACHABLE':<10} {'no-tok':<7} {'w-tok':<7} URL")
    print("-" * 70)
    for url in urls:
        verdict, bs, ts, note = probe(url)
        print(f"{verdict:<10} {str(bs):<7} {str(ts):<7} {url}  {note}")
        rows.append([url, verdict, bs, ts, note])

    if csv_out:
        with open(csv_out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["url", "reachable", "status_no_token", "status_with_token", "note"])
            w.writerows(rows)
        print(f"\nWrote {csv_out}")

    ys = sum(1 for r in rows if r[1] == "Y")
    print(f"\n{ys}/{len(rows)} endpoints parse the Bearer token (REACHABLE=Y). "
          "Verify JDK build + AVX-512 on those hosts, then patch.")


if __name__ == "__main__":
    main()
