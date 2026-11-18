#!/usr/bin/env python3
"""
Java4Shell (CVE-2026-114938) — batch reachability sweep. DEFENSIVE / non-destructive.

Reads a list of URLs (one per line, '#' comments allowed) and prints a
Y / UNKNOWN table of whether sending a Bearer token changes each response.
Sends only harmless, well-formed Base64 — never the exploit payload.

NOT CONCLUSIVE: Y means the token is provably parsed; UNKNOWN proves nothing
(a server can silently Base64-decode the token and reply identically). Patch
in-range JDKs now regardless of what this prints.

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
            return r.status, r.read(4096), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(4096) if e.fp else b""), dict(e.headers or {})
    except Exception as e:
        return None, str(e).encode(), {}


def _www_auth_bearer(headers):
    for k, v in headers.items():
        if k.lower() == "www-authenticate" and "bearer" in v.lower():
            return v
    return None


def probe(url, samples=3):
    # Control baseline: repeated no-token calls. Dynamic Pix payloads re-sign
    # themselves, so BODY is ignored; only status + WWW-Authenticate count.
    controls = [_get(url, {"User-Agent": "j4s-sweep"}) for _ in range(max(2, samples))]
    if controls[0][0] is None:
        return "ERR", None, None, controls[0][1].decode(errors="replace")[:60]
    ctrl_statuses = {c[0] for c in controls}
    ctrl_www = _www_auth_bearer(controls[0][2])
    b_status = controls[0][0]

    t_status, _t_body, t_headers = _get(
        url, {"User-Agent": "j4s-sweep", "Authorization": f"Bearer {BENIGN_BEARER}"}
    )
    t_www = _www_auth_bearer(t_headers)

    if len(ctrl_statuses) > 1:
        return "UNKNOWN", f"{sorted(ctrl_statuses)}", t_status, "baseline noisy"
    if (t_status != b_status) or (t_www and not ctrl_www):
        reason = "WWW-Authenticate: Bearer" if (t_www and not ctrl_www) else "status change"
        return "Y", b_status, t_status, reason
    # Identical response proves nothing: silent decode looks the same. Not "safe".
    return "UNKNOWN", b_status, t_status, "identical resp (not conclusive)"


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
    print(f"{'PARSED':<10} {'no-tok':<7} {'w-tok':<7} URL")
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
    unk = sum(1 for r in rows if r[1] == "UNKNOWN")
    print(f"\nY={ys} (conclusively parse the token)  UNKNOWN={unk} (NOT safe — "
          "cannot tell from outside).")
    print("This sweep does not clear anything. Patch every in-range JDK now and "
          "confirm with --local + check_classpath.py on each host.")


if __name__ == "__main__":
    main()
