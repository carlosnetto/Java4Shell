# Java4Shell (CVE-2026-114938) — exposure toolkit

Defensive, **non-destructive** tooling to check your own infrastructure for the
OpenJDK Base64-decoder RCE disclosed with Oracle's November 17 2026 CPU.

> None of these scripts send an exploit or malformed-Base64 payload. They send
> only harmless, well-formed input and inspect local files. They tell you
> whether the **attack surface is present**, not how to attack it.

## ⚠️ The remote probe is NOT a vulnerability test — patch now regardless

The remote checks (`java4shell_check.py <url>`, `sweep.py`) are a **weak, one-way
signal**, not a verdict:

- **`Y` is conclusive** — the server is provably parsing the Bearer token.
- **`N` / `UNKNOWN` proves nothing.** A server can **silently Base64-decode the
  token — reaching the exact vulnerable code path — and return an identical
  response** (the token is optional on an anonymous endpoint). That decode is
  invisible from outside. **`N` means "cannot tell," never "safe."**

So a clean remote result **does not clear a host**. The correct action is to
**patch every in-range JDK now** (or apply the `-XX:-UseBASE64Intrinsics`
stopgap), and confirm on the host with `--local` + `check_classpath.py`. The
definitive answer always lives on the host, never in a remote probe.

## What the bug actually is

- **CVE-2026-114938** ("Java4Shell"). **Not** Log4Shell, **not** Spring4Shell,
  **not** deserialization or JNDI.
- Memory-corruption bug in OpenJDK's **fast (AVX-512) Base64 decoder intrinsic**.
  Malformed Base64 decoded by a vulnerable JVM can corrupt memory →
  **unauthenticated RCE**.
- Why it matters even on a no-auth endpoint: a **JWT Bearer token is Base64**.
  If Spring Security's resource-server support is on the classpath,
  `BearerTokenAuthenticationFilter` **Base64-decodes the token before** deciding
  it is invalid — so attacker-controlled Base64 reaches the decoder with no
  credentials required.

## You are exploitable only if ALL THREE are true

1. **Vulnerable JDK build** — Java **17.0.6+, 21, 25, or 27** in the affected
   range. Standard **Java 8 / 11 are not affected**.
2. **AVX-512 CPU** — the bug is in the AVX-512 intrinsic. Host is in range only
   if `/proc/cpuinfo` shows all of: `avx512f avx512bw avx512vbmi bmi2`.
   **ARM (Graviton, Apple Silicon) is not affected via this path.**
3. **Something decodes the attacker's Base64** — Spring bearer filter on the
   path, or your own `Base64.getDecoder()` on request input.

## Fix

Patch to: **17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, 8u513-perf,
Corretto 17.0.21.1.2**.

**Stopgap when you can't patch yet** (requires JVM restart, not a replacement
for the patch):

- `-XX:-UseBASE64Intrinsics`  (preferred)
- `-XX:UseAVX=2`  (Intel/AMD **only** — breaks JVM startup on ARM)

## Scripts

| Script | What it does | Run |
|---|---|---|
| `java4shell_check.py` | Single-URL Bearer-reachability probe **and** `--local` JVM-build + CPU verdict | `python3 java4shell_check.py https://host/pix/x` / `--local` |
| `sweep.py` | Batch reachability over a URL list, optional CSV | `python3 sweep.py endpoints.txt --csv results.csv` |
| `check_classpath.py` | Scans jars/fat-jars for the resource-server bearer filter | `python3 check_classpath.py /opt/app/lib` |
| `endpoints.txt` | URL list for `sweep.py` | edit, one URL per line |

### Reading the results

- **PARSED: Y (conclusive)** → the token provably changes the response (status
  change or `WWW-Authenticate: Bearer`). The decode path is reachable pre-auth.
  Not proof of RCE by itself — run `--local` on the host and patch.
- **PARSED: UNKNOWN** → identical response with and without the token, or a
  noisy baseline. **This is not a negative.** Silent decoding is
  indistinguishable from no decoding. Patch anyway.
- **Definitive verdict** is the `--local` check on the host: in-range build
  **AND** AVX-512. Remote results never clear a host.

**Note on dynamic Pix payloads:** `cob`/`cobv` responses embed a server
timestamp (`calendario.apresentacao`) and are **re-signed on every request**, so
the response body changes on its own. The probe therefore does **not** use body
differences as a signal — it takes a control baseline of several no-token calls
(`--samples`, default 3) and decides only on the HTTP **status code** and a
**`WWW-Authenticate: Bearer`** header. (Thanks to the reviewer who caught the
original body-diff false positive against a re-signing endpoint.)

## Sources

- CISA alert: https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching
- Tenable FAQ: https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability
- Qualys (mitigation + fixed builds): https://blog.qualys.com/vulnerabilities-threat-research/2026/11/17/how-to-find-mitigate-and-patch-the-critical-java4shell-flaw-cve-2026-114938-now
- SentinelOne (AVX-512 precondition): https://www.sentinelone.com/blog/java4shell-vulnerability-in-openjdk-enables-rce-on-avx-512-cpus/

*Verify fixed build numbers against Oracle's advisory directly — some sources
reported slightly different build strings on release day.*
