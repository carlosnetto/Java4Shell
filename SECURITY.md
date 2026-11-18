# Scope & responsible use

This toolkit is **defensive and non-destructive**. It contains no exploit: the
remote probes send only well-formed, benign HTTP requests, and the local checks
only read JVM and CPU state. It exists to help operators determine whether their
own systems are exposed to **Java4Shell (CVE-2026-114938)** and to prioritize
patching.

## Authorization

- Run the remote probes (`java4shell_check.py`, `sweep.py`) **only** against
  infrastructure you own or are **explicitly authorized** to test.
- For third-party systems (banks, PSPs, vendors, partners), do **not** probe.
  Use **responsible disclosure**: contact the organization's security team,
  share your findings, and let them run the local checks on their own hosts.
- The reachability probe only tells you whether an endpoint parses an
  `Authorization: Bearer` header. It is **not** proof of exploitability.

## Definitive verdict

Whether a host is actually exploitable is determined **on the host**, by its
owner, with the local check: an in-range JDK build **and** a CPU exposing the
AVX-512 flags (`avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`). ARM (Graviton,
Apple Silicon) is not affected via this path. Remote CPU/architecture cannot be
reliably inferred.

## Remediation

Patch to the fixed builds (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 /
8u513-perf / Corretto 17.0.21.1.2). When patching must wait, a rolling restart
with `-XX:-UseBASE64Intrinsics` neutralizes the flaw without downtime.

See `README.md` for details and sources.
