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

Dynamic Pix payloads re-sign themselves on every request (the body changes on
its own), so body differences are NOT used as a signal. The probe takes a
control baseline of several no-token calls, then trusts only the HTTP status
code and a WWW-Authenticate: Bearer header to decide if the token is parsed.

Usage:
  python3 java4shell_check.py https://your-qr-endpoint.example/pix/abc123
  python3 java4shell_check.py https://host/pix/x --samples 5   # more baseline calls
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
            return r.status, r.read(4096), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(4096) if e.fp else b""), dict(e.headers or {})
    except Exception as e:
        return None, str(e).encode(), {}


def _www_auth_bearer(headers):
    """Return the WWW-Authenticate value if it advertises Bearer, else None."""
    for k, v in headers.items():
        if k.lower() == "www-authenticate" and "bearer" in v.lower():
            return v
    return None


def check_remote(url, samples=3):
    """Reachability probe robust to self-changing (re-signed) payloads.

    Dynamic Pix payloads embed a server timestamp and are re-signed every call,
    so the BODY changes on its own — it is NOT a usable signal. We first take a
    control baseline of several no-token calls to measure that natural variance,
    then rely on signals that do NOT move with the payload: the HTTP status code
    and a WWW-Authenticate: Bearer header (emitted by Spring's bearer filter when
    it rejects a token). Body is used only if the baseline proves it is stable.
    """
    hdr = {"User-Agent": "j4s-reachability-check"}

    # --- Control: repeated no-token calls to learn natural variance. ---
    controls = [_get(url, hdr) for _ in range(max(2, samples))]
    if controls[0][0] is None:
        print(f"ERROR  could not reach {url}: "
              f"{controls[0][1].decode(errors='replace')}")
        return
    ctrl_statuses = {c[0] for c in controls}
    ctrl_bodies = {c[1] for c in controls}
    body_volatile = len(ctrl_bodies) > 1
    status_stable = len(ctrl_statuses) == 1
    ctrl_status = controls[0][0]
    ctrl_www = _www_auth_bearer(controls[0][2])

    # --- Probe: one call WITH a syntactically valid junk Bearer token. ---
    t_status, t_body, t_headers = _get(
        url, {**hdr, "Authorization": f"Bearer {BENIGN_BEARER}"}
    )
    t_www = _www_auth_bearer(t_headers)

    print(f"  no-token  : status {sorted(ctrl_statuses)} over {len(controls)} calls"
          f"  (body {'VARIES on its own' if body_volatile else 'stable'})")
    print(f"  w/ token  : status {t_status}")

    signals = []
    if status_stable and t_status != ctrl_status:
        signals.append(f"status changed {ctrl_status} -> {t_status} when the token "
                       "was sent (control status was stable)")
    if t_www and not ctrl_www:
        signals.append(f'response added "WWW-Authenticate: {t_www}" — a bearer '
                       "filter is actively parsing the token")
    if not body_volatile and t_body != controls[0][1]:
        signals.append("body changed vs a stable baseline when the token was sent")

    if signals:
        print("REACHABLE: Y  -- the Bearer-parsing path appears active:")
        for s in signals:
            print(f"            - {s}")
        print("          Verify the --local check on the host, then patch.")
    elif not status_stable:
        print("REACHABLE: ?  -- the no-token status itself varied "
              f"{sorted(ctrl_statuses)}; result inconclusive.\n"
              "          Re-run against a quieter target or raise --samples.")
    else:
        note = ("          (Body changes on its own, so it was ignored; verdict "
                "is based on status + WWW-Authenticate.)\n") if body_volatile else ""
        print("REACHABLE: N  -- status is unchanged and no bearer-auth header "
              "appeared with the token.\n" + note +
              "          This endpoint does not appear to parse the Authorization "
              "header. Still patch the JDK — other inputs may decode Base64.")


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
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if args[0] == "--local":
        check_local()
    else:
        samples = 3
        if "--samples" in args:
            samples = int(args[args.index("--samples") + 1])
        check_remote(args[0], samples=samples)
