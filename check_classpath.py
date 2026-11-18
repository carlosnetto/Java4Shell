#!/usr/bin/env python3
"""
Does a Java service actually have Spring Security's Bearer-token filter on its
classpath? If not, the "Spring decodes my Authorization header even though I
don't use it" path does not exist for that service.

This is a LOCAL inspection of jars/fat-jars you point it at. No network, no exec.

Usage:
  python3 check_classpath.py /path/to/service.jar
  python3 check_classpath.py /opt/app/lib         # scans a directory of jars
"""

import sys
import os
import zipfile

# The jar that contains BearerTokenAuthenticationFilter (the class that
# Base64-decodes the token before validating it).
MARKERS = [
    "spring-security-oauth2-resource-server",
    "BearerTokenAuthenticationFilter.class",
    "org/springframework/security/oauth2/server/resource",
]


def scan_jar(path):
    hits = []
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            # fat jar? look at nested jar names too
            flat = "\n".join(names)
            for m in MARKERS:
                if m in flat:
                    hits.append(m)
    except zipfile.BadZipFile:
        return None
    return hits


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    target = sys.argv[1]

    jars = []
    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fn in files:
                if fn.endswith(".jar"):
                    jars.append(os.path.join(root, fn))
    else:
        jars = [target]

    any_hit = False
    for j in jars:
        hits = scan_jar(j)
        if hits is None:
            continue
        if hits:
            any_hit = True
            print(f"BEARER PATH PRESENT: {j}")
            for h in hits:
                print(f"    - {h}")

    print()
    if any_hit:
        print("RESULT: Y -- resource-server / bearer-token support is present. "
              "An attacker-supplied Bearer token WILL be Base64-decoded. "
              "Treat this service as in-scope and patch the JDK.")
    else:
        print("RESULT: N -- no resource-server bearer filter found in the scanned "
              "jars. This specific Spring path does not apply.\n"
              "        (Still patch: your own Base64.getDecoder() calls, or other "
              "libraries, can reach the vulnerable decoder.)")


if __name__ == "__main__":
    main()
