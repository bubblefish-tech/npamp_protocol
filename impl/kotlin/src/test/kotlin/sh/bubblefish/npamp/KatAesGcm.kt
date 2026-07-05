// Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google
// Project Wycheproof vectors (C2SP/wycheproof), via the dependency-free flat
// corpus _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).
//
// These vectors are authored by an independent authority and encode KNOWN ATTACKS
// (truncated tags, modified ciphertext) that our self-generated golden vectors never
// include -- so a shared bug between our impls cannot pass them.
//
// Trick: sealAes256Gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with
// seq=0 the nonce IS the given IV, so each vector exercises the REAL seal/open path.
//
// Exit 0 iff every vector behaves exactly as Wycheproof labels it. Kotlin port of the
// Python reference runner kat_aesgcm_wycheproof.py (passes 66/66).
package sh.bubblefish.npamp

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.system.exitProcess

object KatAesGcm {

    /** Decodes a lowercase/uppercase hex string into bytes; "" -> empty array. */
    private fun fromHex(s: String): ByteArray {
        val n = s.length
        require(n and 1 == 0) { "odd-length hex: $s" }
        val out = ByteArray(n / 2)
        var i = 0
        while (i < n) {
            val hi = Character.digit(s[i], 16)
            val lo = Character.digit(s[i + 1], 16)
            require(hi >= 0 && lo >= 0) { "bad hex: $s" }
            out[i / 2] = ((hi shl 4) or lo).toByte()
            i += 2
        }
        return out
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val tsv = if (args.isNotEmpty()) {
            Paths.get(args[0])
        } else {
            Paths.get("..", "..", "_shared", "wycheproof", "aesgcm_kat.tsv")
        }

        var total = 0
        var passed = 0
        val fails = ArrayList<String>()

        val lines = Files.readAllLines(tsv, StandardCharsets.UTF_8)
        for (line in lines) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue
            }
            // Kotlin's split keeps trailing empty fields by default (limit=0), unlike
            // Java's String.split which strips them; aad/msg/ct/tag may be EMPTY.
            val f = line.split("\t")
            check(f.size == 8) { "expected 8 columns, got ${f.size}: $line" }
            val tc = f[0]
            val result = f[1]
            val key = fromHex(f[2])
            val iv = fromHex(f[3])
            val aad = fromHex(f[4])
            val msg = fromHex(f[5])
            val ct = fromHex(f[6])
            val tag = fromHex(f[7])

            val sealed = ByteArray(ct.size + tag.size)
            System.arraycopy(ct, 0, sealed, 0, ct.size)
            System.arraycopy(tag, 0, sealed, ct.size, tag.size)

            var ok = true
            var reason = ""

            when (result) {
                "valid" -> {
                    var gotSealed: ByteArray? = try {
                        Npamp.sealAes256Gcm(key, iv, 0L, aad, msg)
                    } catch (e: RuntimeException) {
                        null
                    }
                    if (gotSealed == null || !gotSealed.contentEquals(sealed)) {
                        ok = false
                        reason = "encrypt mismatch"
                    } else {
                        val gotPt: ByteArray? = try {
                            Npamp.openAes256Gcm(key, iv, 0L, aad, sealed)
                        } catch (e: RuntimeException) {
                            null
                        }
                        if (gotPt == null || !gotPt.contentEquals(msg)) {
                            ok = false
                            reason = "decrypt mismatch"
                        }
                    }
                }
                "invalid" -> {
                    try {
                        Npamp.openAes256Gcm(key, iv, 0L, aad, sealed)
                        ok = false
                        reason = "accepted an invalid vector"
                    } catch (e: RuntimeException) {
                        // correct: rejected
                    }
                }
                else -> { // "acceptable"
                    try {
                        val gotPt = Npamp.openAes256Gcm(key, iv, 0L, aad, sealed)
                        if (!gotPt.contentEquals(msg)) {
                            ok = false
                            reason = "acceptable but wrong plaintext"
                        }
                    } catch (e: RuntimeException) {
                        // rejection is also allowed for acceptable
                    }
                }
            }

            total++
            if (ok) {
                passed++
            } else {
                fails.add("  FAIL tcId=$tc result=$result: $reason")
            }
        }

        println("AES-256-GCM Wycheproof KAT (kotlin): $passed/$total passed")
        var i = 0
        while (i < fails.size && i < 15) {
            println(fails[i])
            i++
        }
        exitProcess(if (fails.isEmpty() && total > 0) 0 else 1)
    }
}
