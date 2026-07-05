"""Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google
Project Wycheproof vectors (C2SP/wycheproof), via the dependency-free flat corpus
_shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).

These vectors are authored by an independent authority and encode KNOWN ATTACKS
(truncated tags, modified ciphertext) that our self-generated golden vectors never
include — so a shared bug between our impls cannot pass them.

Trick: seal_aes256gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with
seq=0 the nonce IS the given IV, so each vector exercises the REAL seal/open path.

Exit 0 iff every vector behaves exactly as Wycheproof labels it. This is the
reference KAT runner the other languages port.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "OPEN" / "impl" / "python"))
from npamp import seal_aes256gcm, open_aes256gcm  # noqa: E402

TSV = Path(sys.argv[1]) if len(sys.argv) > 1 else (ROOT / "_shared" / "wycheproof" / "aesgcm_kat.tsv")


def main() -> int:
    total = passed = 0
    fails = []
    for line in TSV.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        tc, result, key, iv, aad, msg, ct, tag = line.split("\t")
        key, iv, aad = bytes.fromhex(key), bytes.fromhex(iv), bytes.fromhex(aad)
        msg = bytes.fromhex(msg)
        sealed = bytes.fromhex(ct) + bytes.fromhex(tag)
        ok, reason = True, ""
        if result == "valid":
            if seal_aes256gcm(key, iv, 0, aad, msg) != sealed:
                ok, reason = False, "encrypt mismatch"
            elif open_aes256gcm(key, iv, 0, aad, sealed) != msg:
                ok, reason = False, "decrypt mismatch"
        elif result == "invalid":
            try:
                open_aes256gcm(key, iv, 0, aad, sealed)
                ok, reason = False, "accepted an invalid vector"
            except Exception:
                pass  # correct: rejected
        else:  # "acceptable"
            try:
                if open_aes256gcm(key, iv, 0, aad, sealed) != msg:
                    ok, reason = False, "acceptable but wrong plaintext"
            except Exception:
                pass
        total += 1
        if ok:
            passed += 1
        else:
            fails.append((tc, result, reason))

    print(f"AES-256-GCM Wycheproof KAT (python): {passed}/{total} passed")
    for tc, result, reason in fails[:15]:
        print(f"  FAIL tcId={tc} result={result}: {reason}")
    return 0 if not fails and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
