"""Independent crypto KAT: drive N-PAMP's HKDF-Expand through Google/C2SP Wycheproof
HKDF-SHA-256 vectors, via the flat corpus _shared/wycheproof/hkdf_kat.tsv. This
validates the HKDF-Expand primitive (used by the key schedule) against an authority that
never saw our code. Rows for other hashes (sha384) are not computed: this module implements
the Standard profile only, so each such row must be REFUSED with NoSuiteForProfile.
Reference runner; ported to the other languages.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "OPEN" / "impl" / "python"))
from npamp import hkdf_expand, NoSuiteForProfile  # noqa: E402

TSV = Path(sys.argv[1]) if len(sys.argv) > 1 else (ROOT / "_shared" / "wycheproof" / "hkdf_kat.tsv")


def main() -> int:
    total = passed = refused = 0
    fails = []
    for line in TSV.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        tc, h, prk, info, size, okm = line.split("\t")
        total += 1
        try:
            got = hkdf_expand(bytes.fromhex(prk), bytes.fromhex(info), int(size), h == "sha256")
        except NoSuiteForProfile:
            if h != "sha256":
                refused += 1
            else:
                fails.append((tc, h))
            continue
        if h == "sha256" and got.hex() == okm:
            passed += 1
        else:
            fails.append((tc, h))
    print(f"HKDF-Expand Wycheproof KAT (python): {passed} sha256 passed, {refused} non-sha256 refused, {total} total")
    for tc, h in fails[:15]:
        print(f"  FAIL tcId={tc} {h}")
    return 0 if not fails and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
