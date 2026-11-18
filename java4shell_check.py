#!/usr/bin/env python3
"""
Java4Shell (CVE-2026-114938) exposure checker — DEFENSIVE / non-destructive.

It does NOT send any exploit or malformed-Base64 payload. It answers two
questions for YOUR OWN server:

  REMOTE  : Does the endpoint actually parse an Authorization: Bearer token?
            (i.e. is the "Spring decodes it even though I don't use it" path
            reachable on a no-auth endpoint?)  -> attack-surface reachability.

  LOCAL   : Is the JVM build in range AND does the CPU have the AVX-512 flags
            the vulnerable Base64 intrinsic needs?  -> run on each host.

A remote "Y" means: investigate/patch. It does NOT by itself prove RCE —
that also needs the LOCAL conditions true on the host serving the URL.

Usage:
  python3 java4shell_check.py https://your-qr-endpoint.example/pix/abc123
  python3 java4shell_check.py --local          # check this host's JVM + CPU
"""

import sys
import ssl
import base64
import urllib.request
import urllib.error

# A well-formed, harmless Base64 string (decodes to b"not-a-real-token").
# This is deliberately VALID Base64 — it exercises the decode path without
# being the malformed input that triggers the bug.
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


def check_remote(url):
    # Baseline: no auth header at all (your normal, intended request).
    base_status, base_body = _get(url, {"User-Agent": "j4s-reachability-check"})
    if base_status is None:
        print(f"ERROR  could not reach {url}: {base_body.decode(errors='replace')}")
        return

    # Same request, but WITH a syntactically valid junk Bearer token.
    bearer_status, bearer_body = _get(
        url,
        {
            "User-Agent": "j4s-reachability-check",
            "Authorization": f"Bearer {BENIGN_BEARER}",
        },
    )

    changed = (bearer_status != base_status) or (bearer_body != base_body)

    print(f"  no-token  : HTTP {base_status}")
    print(f"  w/ token  : HTTP {bearer_status}")
    if changed:
        print("REACHABLE: Y  -- the server's response CHANGED when a Bearer "
              "token was present.\n"
              "          Something is parsing the Authorization header "
              "(likely Spring Security's bearer filter).\n"
              "          The vulnerable Base64-decode path may be reachable "
              "pre-auth. Verify the LOCAL check on the host, then patch.")
    else:
        print("REACHABLE: N  -- identical response with and without the token; "
              "this endpoint appears to ignore the Authorization header.\n"
              "          (Still patch the JDK — other inputs may decode "
              "Base64. This only clears THIS path.)")


def check_local():
    import platform
    # JVM build
    import subprocess
    try:
        out = subprocess.run(["java", "-version"], capture_output=True, text=True)
        ver = (out.stderr or out.stdout).strip()
    except FileNotFoundError:
        ver = "(java not found on PATH)"
    print("JVM:")
    for line in ver.splitlines():
        print("   ", line)

    # AVX-512 CPU flags (Linux only)
    needed = {"avx512f", "avx512bw", "avx512vbmi", "bmi2"}
    cpu_hit = None
    try:
        with open("/proc/cpuinfo") as f:
            flags = set(f.read().split())
        cpu_hit = needed.issubset(flags)
        print(f"CPU AVX-512 intrinsic flags present: "
              f"{'Y (all 4 present)' if cpu_hit else 'N (missing: ' + ' '.join(sorted(needed - flags)) + ')'}")
    except FileNotFoundError:
        print(f"CPU: /proc/cpuinfo not available on {platform.system()} — "
              "check AVX-512 support another way (not Linux).")

    print("\nVULNERABLE if: JDK build is 17.0.6+/21/25/27 in the affected range "
          "(not 8/11)  AND  CPU AVX-512 flags = Y.")
    print("Fixed builds: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, "
          "8u513-perf, Corretto 17.0.21.1.2.")
    print("Stopgap:      -XX:-UseBASE64Intrinsics  (restart required).")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if sys.argv[1] == "--local":
        check_local()
    else:
        check_remote(sys.argv[1])
