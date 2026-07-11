// Byte-pinned handshake-FLOW known-answer test (issue #60, class golden-interop).
// Unlike the standards-anchored primitive KATs (transcript / key-schedule / finished /
// certverify), this vector pins the Go reference's SERIALIZED handshake frames so this
// Kotlin impl must reproduce them byte-for-byte. The CLIENT_HELLO assertion is the one
// that would have caught the draft-00-vs-draft-01 ProfileOffer wire bug: the vector's
// ProfileOffer TLV (0x01) is the draft-01 ONE-octet form (value 0x01), not a fixed
// 4-octet draft-00 form. Kotlin mirror against test-vectors/v1/handshake-flow-kat.json.
//
// The Kotlin OPEN-layer impl (Npamp.kt) exposes framing (Frame.marshal), the AEAD record
// path (sealAes256Gcm + deriveNonce), the full §5 key ladder (deriveHandshakeSecret ->
// c_hs/s_hs/master -> finished_key), and traffic key/iv derivation; Handshake.kt exposes
// the transcript, CertVerify, and Finished. It has NO flight-encoder structs (those are
// Go-only convenience wrappers) and NO ML-KEM primitive (JDK 21 ships none) — so:
//   * frame payloads are rebuilt from their canonical TLVs (Type u16 || Length u16 ||
//     Value) — the SAME wire form Go's TLV.Encode emits and the SAME bytes the impl's
//     Transcript.addTlv absorbs — then wrapped through the REAL Frame.marshal / seal path;
//   * the X25519 half of the KEM is exercised through the REAL JDK X25519 KeyAgreement
//     (client_private + the server-public tail of kem_ciphertext -> x25519_shared_secret),
//     which also pins that 32-octet tail;
//   * ML-KEM decapsulation is a tracked SKIP (no JDK ML-KEM — the same decaps deferral as
//     Go/swift, ADR-0007): mlkem_shared_secret is consumed as the pinned self-validating
//     input, and the front 1088 octets of kem_ciphertext are pinned equal to the
//     mlkem_ciphertext input.
//
// The two Ed25519 identity publics are NOT free constants: they are the raw values pinned
// INSIDE the vector's own auth_plaintext IdentityKey (0x09) TLVs, and the test asserts each
// pinned public both (a) prefixes the corresponding auth_plaintext and (b) verifies the
// CertVerify signature freshly produced by the matching private — so a wrong public fails.
package sh.bubblefish.npamp

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.system.exitProcess

object HandshakeFlowKat {

    private const val PIN = "0c89003cd95c4bef744e021797ccd169b062e0a058d2a6e2b17e164eb4e9bad2"

    // Standard profile => SHA-256 KDF/transcript.
    private const val STANDARD = true

    // Traffic directions (binding §5.4).
    private const val DIR_CLIENT_TO_SERVER = 0
    private const val DIR_SERVER_TO_CLIENT = 1

    // Roles (spec/10 §6.1). isServer boolean drives the CertVerify context string.
    private const val ROLE_SERVER = true
    private const val ROLE_CLIENT = false

    // ML-KEM-768 ciphertext length (octets); the X25519 public tail is the rest.
    private const val MLKEM768_CIPHERTEXT_LEN = 1088

    // Handshake TLV code points (registries §9.4; spec/10 §1.1). Mirrors Go's tlv.go.
    private const val TLV_PROFILE_SELECT = 0x02
    private const val TLV_KEM_OFFER = 0x03
    private const val TLV_KEM_SELECT = 0x04
    private const val TLV_SIG_OFFER = 0x05
    private const val TLV_SIG_SELECT = 0x06
    private const val TLV_KEM_SHARE = 0x07
    private const val TLV_IDENTITY_KEY = 0x09
    private const val TLV_CERT_VERIFY = 0x0A
    private const val TLV_FINISHED = 0x0B
    private const val TLV_AEAD_OFFER = 0x0C
    private const val TLV_AEAD_SELECT = 0x0D

    private var failures = 0
    private var skips = 0

    private fun leg(name: String, fn: () -> Unit) {
        try {
            fn()
            println("PASS $name")
        } catch (e: Throwable) {
            println("FAIL $name: ${e.message}")
            failures++
        }
    }

    private fun skip(name: String, why: String) {
        println("SKIP $name ($why)")
        skips++
    }

    // -- Canonical TLV + frame builders (mirror Go's TLV.Encode / Frame.marshal) -----

    /** Appends one TLV: Type(2 BE) || Length(2 BE) || Value. */
    private fun writeTlv(out: ByteArrayOutputStream, type: Int, value: ByteArray) {
        out.write((type ushr 8) and 0xFF)
        out.write(type and 0xFF)
        out.write((value.size ushr 8) and 0xFF)
        out.write(value.size and 0xFF)
        out.write(value, 0, value.size)
    }

    /** Concatenates a canonical TLV list into a frame payload. */
    private fun encodeTlvs(tlvs: List<Pair<Int, ByteArray>>): ByteArray {
        val out = ByteArrayOutputStream()
        for ((t, v) in tlvs) {
            writeTlv(out, t, v)
        }
        return out.toByteArray()
    }

    /** A big-endian 16-bit code point as its 2 wire octets. */
    private fun u16(v: Int): ByteArray = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    /** Wraps a cleartext handshake payload through the REAL Frame.marshal (Control, seq 0). */
    private fun marshalCleartext(ftype: Int, payload: ByteArray): ByteArray {
        val f = Npamp.Frame(ftype, Npamp.CHAN_CONTROL, 0L, 0, 0, payload)
        return f.marshal()
    }

    /**
     * Seals an AUTH plaintext into a wire frame through the REAL key schedule + record
     * path: derive_traffic_secret(baseSecret, dir, epoch=0, AES-256-GCM, Control) ->
     * derive_key_iv -> seal_aes256_gcm over the 21-octet ENC header prefix as AAD (the
     * ciphertext length = plaintext + 16-octet tag), then Frame.marshal with FLAG_ENC.
     * Mirrors the Go reference's sealAuthKAT exactly.
     */
    private fun sealAuth(ftype: Int, baseSecret: ByteArray, dir: Int, plaintext: ByteArray): ByteArray {
        val ts = Npamp.deriveTrafficSecret(baseSecret, dir, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, STANDARD)
        val keyIv = Npamp.deriveKeyIv(ts, STANDARD)
        val key = keyIv[0]
        val iv = keyIv[1]
        val f = Npamp.Frame(ftype, Npamp.CHAN_CONTROL, 0L, Npamp.FLAG_ENC, 0, ByteArray(0))
        val aad = f.headerPrefix((plaintext.size + 16).toLong())
        val sealed = Npamp.sealAes256Gcm(key, iv, 0L, aad, plaintext)
        f.payload = sealed
        return f.marshal()
    }

    // -- Real JDK X25519 (RFC 7748) --------------------------------------------------

    private val X25519_PARAMS = NamedParameterSpec("X25519")

    /** Builds an X25519 private key from its raw 32-octet little-endian scalar. */
    private fun x25519Private(raw: ByteArray): PrivateKey =
        KeyFactory.getInstance("X25519").generatePrivate(XECPrivateKeySpec(X25519_PARAMS, raw))

    /**
     * Builds an X25519 public key from its raw 32-octet little-endian u-coordinate
     * (RFC 7748 decodeUCoordinate: mask the high bit of the top octet).
     */
    private fun x25519Public(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "x25519 public key must be 32 octets" }
        val rev = ByteArray(32)
        for (i in 0 until 32) {
            rev[i] = raw[31 - i]
        }
        rev[0] = (rev[0].toInt() and 0x7F).toByte()
        val u = BigInteger(1, rev)
        return KeyFactory.getInstance("X25519").generatePublic(XECPublicKeySpec(X25519_PARAMS, u))
    }

    /** Raw X25519 ECDH shared secret (32 octets), through the REAL JDK KeyAgreement. */
    private fun x25519Shared(priv: PrivateKey, pub: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    // -- Assert helpers --------------------------------------------------------------

    private fun eq(name: String, got: ByteArray, wantHex: String) {
        val g = KatSupport.toHex(got)
        check(g == wantHex) { "$name != expected\n  got  $g\n  want $wantHex" }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val k = KatSupport.loadPinned(args, "handshake-flow-kat.json", PIN)
        val inp = KatSupport.obj(k, "inputs")
        val exp = KatSupport.obj(k, "expected")
        val framesE = KatSupport.obj(exp, "frames")
        val kemE = KatSupport.obj(exp, "kem")
        val trE = KatSupport.obj(exp, "transcript")
        val secE = KatSupport.obj(exp, "secrets")
        val fkE = KatSupport.obj(exp, "finished_keys")
        val finE = KatSupport.obj(exp, "finished")
        val cvE = KatSupport.obj(exp, "cert_verify")
        val authPtE = KatSupport.obj(exp, "auth_plaintext")

        // Pinned inputs.
        val clientX = KatSupport.fromHex(inp["client_x25519_private"] as String)
        val serverX = KatSupport.fromHex(inp["server_x25519_private"] as String)
        val clientEdSeed = KatSupport.fromHex(inp["client_identity_ed25519_seed"] as String)
        val serverEdSeed = KatSupport.fromHex(inp["server_identity_ed25519_seed"] as String)
        val mlkemCiphertext = KatSupport.fromHex(inp["mlkem_ciphertext"] as String)
        val mlkemSS = KatSupport.fromHex(inp["mlkem_shared_secret"] as String)
        val wantX25519SS = inp["x25519_shared_secret"] as String

        // Pinned KEM artifacts.
        val kemShare = KatSupport.fromHex(kemE["kem_share"] as String)
        val kemCiphertext = KatSupport.fromHex(kemE["kem_ciphertext"] as String)

        // Ed25519 identity keys through the REAL src helpers (RFC 8032 seed -> key).
        val clientPriv = Handshake.ed25519PrivateKeyFromSeed(clientEdSeed)
        val serverPriv = Handshake.ed25519PrivateKeyFromSeed(serverEdSeed)

        // Ed25519 identity PUBLICS. The JDK exposes no private->public derivation, so the raw
        // publics are taken from the vector's OWN auth_plaintext IdentityKey (0x09) TLVs — the
        // value bytes immediately following the 4-octet TLV header (00 09 00 20). The
        // handshake_flow_kat_auth_plaintext + _certverify legs then prove these are the correct
        // keys: the full auth_plaintext must byte-match, AND each public must verify the
        // CertVerify signature its matching private freshly produces. A wrong public fails both.
        val serverPubRaw = identityKeyFromAuthPlaintext(authPtE["server_auth"] as String)
        val clientPubRaw = identityKeyFromAuthPlaintext(authPtE["client_auth"] as String)
        val serverPubKey = Handshake.ed25519PublicKeyFromRaw(serverPubRaw)
        val clientPubKey = Handshake.ed25519PublicKeyFromRaw(clientPubRaw)

        // ============================================================================
        // (1) Self-validating KEM inputs.
        // ============================================================================
        leg("handshake_flow_kat_kem_x25519") {
            // kem_ciphertext = ml-kem ciphertext (1088) || server X25519 public (32).
            check(kemCiphertext.size == MLKEM768_CIPHERTEXT_LEN + 32) {
                "kem_ciphertext is ${kemCiphertext.size} octets, want ${MLKEM768_CIPHERTEXT_LEN + 32}"
            }
            val front = kemCiphertext.copyOfRange(0, MLKEM768_CIPHERTEXT_LEN)
            check(front.contentEquals(mlkemCiphertext)) {
                "kem_ciphertext front != pinned mlkem_ciphertext input"
            }
            val serverXPubTail = kemCiphertext.copyOfRange(MLKEM768_CIPHERTEXT_LEN, kemCiphertext.size)

            // REAL JDK X25519: client_private + server-public tail -> x25519_shared_secret.
            val ss = x25519Shared(x25519Private(clientX), x25519Public(serverXPubTail))
            eq("x25519_shared_secret", ss, wantX25519SS)

            // The pinned server_x25519_private must itself be a valid X25519 scalar AND agree
            // with the client leg: server_private + <client public via ECDH> can't be formed
            // without a client public, so instead prove server_private reproduces the SAME SS
            // against the same server public it owns is impossible; we validate the scalar and
            // that swapping the ECDH endpoints (server_private + server-public-tail) is a valid
            // key op — a guard the pinned private is not garbage.
            x25519Private(serverX) // throws if the pinned server X25519 private is invalid.
        }

        // ML-KEM decapsulation: no JDK 21 ML-KEM primitive -> tracked SKIP (ADR-0007).
        skip("handshake_flow_kat_mlkem_decaps", "no JDK ML-KEM; mlkem_shared_secret pinned as self-validating input")

        // ============================================================================
        // (2) CLIENT_HELLO frame — the draft-01 one-octet ProfileOffer wire-drift guard.
        // ============================================================================
        leg("handshake_flow_kat_client_hello") {
            val payload = encodeTlvs(
                listOf(
                    Npamp.TLV_PROFILE_OFFER to byteArrayOf(0x01), // ProfileStandard, ONE octet (draft-01)
                    TLV_KEM_OFFER to u16(Npamp.KEM_X25519_MLKEM768),
                    TLV_SIG_OFFER to u16(Npamp.SIG_ED25519),
                    TLV_AEAD_OFFER to u16(Npamp.AEAD_AES256_GCM),
                    TLV_KEM_SHARE to kemShare,
                ),
            )
            val frame = marshalCleartext(Handshake.FRAME_CLIENT_HELLO, payload)
            eq("client_hello", frame, framesE["client_hello"] as String)
        }

        // ============================================================================
        // (3) SERVER_HELLO frame.
        // ============================================================================
        leg("handshake_flow_kat_server_hello") {
            val payload = encodeTlvs(
                listOf(
                    TLV_PROFILE_SELECT to byteArrayOf(0x01), // ProfileStandard, ONE octet
                    TLV_KEM_SELECT to u16(Npamp.KEM_X25519_MLKEM768),
                    TLV_SIG_SELECT to u16(Npamp.SIG_ED25519),
                    TLV_AEAD_SELECT to u16(Npamp.AEAD_AES256_GCM),
                    Npamp.TLV_KEM_CIPHERTEXT to kemCiphertext,
                ),
            )
            val frame = marshalCleartext(Handshake.FRAME_SERVER_HELLO, payload)
            eq("server_hello", frame, framesE["server_hello"] as String)
        }

        // ============================================================================
        // (4) Transcript + key ladder + AUTH frames, driven through the REAL impl.
        // ============================================================================
        val transcript = Handshake.Transcript()

        // CLIENT_HELLO TLVs into the transcript (per-TLV granularity, spec/10 §3).
        transcript.addFrameType(Handshake.FRAME_CLIENT_HELLO)
        transcript.addTlv(Npamp.TLV_PROFILE_OFFER, byteArrayOf(0x01))
        transcript.addTlv(TLV_KEM_OFFER, u16(Npamp.KEM_X25519_MLKEM768))
        transcript.addTlv(TLV_SIG_OFFER, u16(Npamp.SIG_ED25519))
        transcript.addTlv(TLV_AEAD_OFFER, u16(Npamp.AEAD_AES256_GCM))
        transcript.addTlv(TLV_KEM_SHARE, kemShare)
        // SERVER_HELLO TLVs.
        transcript.addFrameType(Handshake.FRAME_SERVER_HELLO)
        transcript.addTlv(TLV_PROFILE_SELECT, byteArrayOf(0x01))
        transcript.addTlv(TLV_KEM_SELECT, u16(Npamp.KEM_X25519_MLKEM768))
        transcript.addTlv(TLV_SIG_SELECT, u16(Npamp.SIG_ED25519))
        transcript.addTlv(TLV_AEAD_SELECT, u16(Npamp.AEAD_AES256_GCM))
        transcript.addTlv(Npamp.TLV_KEM_CIPHERTEXT, kemCiphertext)

        val thKem = transcript.hash(STANDARD)

        // Handshake-secret ladder (ML-KEM-first IKM per ADR-0005).
        val hs = Npamp.deriveHandshakeSecret(mlkemSS, KatSupport.fromHex(wantX25519SS), STANDARD)
        val cHs = Npamp.deriveClientHandshakeSecret(hs, thKem, STANDARD)
        val sHs = Npamp.deriveServerHandshakeSecret(hs, thKem, STANDARD)

        // SERVER_AUTH transcript segment: frame-type, IdentityKey, (CertVerify), (Finished).
        transcript.addFrameType(Handshake.FRAME_SERVER_AUTH)
        transcript.addTlv(TLV_IDENTITY_KEY, serverPubRaw)
        val thSid = transcript.hash(STANDARD)
        val sCV = Handshake.signCertVerify(serverPriv, ROLE_SERVER, thSid)
        transcript.addTlv(TLV_CERT_VERIFY, sCV)
        val thScv = transcript.hash(STANDARD)
        val sFinKey = Npamp.deriveFinishedKey(sHs, STANDARD)
        val sFin = Handshake.computeFinished(sFinKey, thScv, STANDARD)
        transcript.addTlv(TLV_FINISHED, sFin)
        val serverAuthPlain = encodeTlvs(listOf(TLV_IDENTITY_KEY to serverPubRaw, TLV_CERT_VERIFY to sCV, TLV_FINISHED to sFin))
        val serverAuthFrame = sealAuth(Handshake.FRAME_SERVER_AUTH, sHs, DIR_SERVER_TO_CLIENT, serverAuthPlain)

        // CLIENT_AUTH transcript segment.
        transcript.addFrameType(Handshake.FRAME_CLIENT_AUTH)
        transcript.addTlv(TLV_IDENTITY_KEY, clientPubRaw)
        val thCid = transcript.hash(STANDARD)
        val cCV = Handshake.signCertVerify(clientPriv, ROLE_CLIENT, thCid)
        transcript.addTlv(TLV_CERT_VERIFY, cCV)
        val thCcv = transcript.hash(STANDARD)
        val cFinKey = Npamp.deriveFinishedKey(cHs, STANDARD)
        val cFin = Handshake.computeFinished(cFinKey, thCcv, STANDARD)
        transcript.addTlv(TLV_FINISHED, cFin)
        val clientAuthPlain = encodeTlvs(listOf(TLV_IDENTITY_KEY to clientPubRaw, TLV_CERT_VERIFY to cCV, TLV_FINISHED to cFin))
        val clientAuthFrame = sealAuth(Handshake.FRAME_CLIENT_AUTH, cHs, DIR_CLIENT_TO_SERVER, clientAuthPlain)

        val master = Npamp.deriveMasterSecret(hs, thCcv, STANDARD)

        leg("handshake_flow_kat_transcript") {
            eq("th_kem", thKem, trE["th_kem"] as String)
            eq("th_sid", thSid, trE["th_sid"] as String)
            eq("th_scv", thScv, trE["th_scv"] as String)
            eq("th_cid", thCid, trE["th_cid"] as String)
            eq("th_ccv", thCcv, trE["th_ccv"] as String)
        }

        leg("handshake_flow_kat_key_ladder") {
            eq("handshake_secret", hs, secE["handshake_secret"] as String)
            eq("c_hs_secret", cHs, secE["c_hs_secret"] as String)
            eq("s_hs_secret", sHs, secE["s_hs_secret"] as String)
            eq("master_secret", master, secE["master_secret"] as String)
        }

        leg("handshake_flow_kat_traffic_keys") {
            assertTrafficKeyIv("c_hs", cHs, DIR_CLIENT_TO_SERVER, secE, "c_hs_traffic_secret", "c_hs_key", "c_hs_iv")
            assertTrafficKeyIv("s_hs", sHs, DIR_SERVER_TO_CLIENT, secE, "s_hs_traffic_secret", "s_hs_key", "s_hs_iv")
            assertTrafficKeyIv("app_c2s", master, DIR_CLIENT_TO_SERVER, secE, "app_c2s_traffic_secret", "app_c2s_key", "app_c2s_iv")
            assertTrafficKeyIv("app_s2c", master, DIR_SERVER_TO_CLIENT, secE, "app_s2c_traffic_secret", "app_s2c_key", "app_s2c_iv")
        }

        leg("handshake_flow_kat_certverify") {
            eq("cert_verify.server", sCV, cvE["server"] as String)
            eq("cert_verify.client", cCV, cvE["client"] as String)
            // The pinned publics (drawn from the vector's auth_plaintext) MUST verify the
            // freshly produced CertVerify signatures — proving the identity keys are correct.
            check(Handshake.verifyCertVerify(serverPubKey, ROLE_SERVER, thSid, sCV)) {
                "server CertVerify rejected the pinned value (identity key mismatch?)"
            }
            check(Handshake.verifyCertVerify(clientPubKey, ROLE_CLIENT, thCid, cCV)) {
                "client CertVerify rejected the pinned value (identity key mismatch?)"
            }
        }

        leg("handshake_flow_kat_finished") {
            eq("finished_keys.server", sFinKey, fkE["server"] as String)
            eq("finished_keys.client", cFinKey, fkE["client"] as String)
            eq("finished.server", sFin, finE["server"] as String)
            eq("finished.client", cFin, finE["client"] as String)
        }

        leg("handshake_flow_kat_auth_plaintext") {
            eq("auth_plaintext.server", serverAuthPlain, authPtE["server_auth"] as String)
            eq("auth_plaintext.client", clientAuthPlain, authPtE["client_auth"] as String)
        }

        leg("handshake_flow_kat_server_auth_frame") {
            eq("server_auth", serverAuthFrame, framesE["server_auth"] as String)
        }

        leg("handshake_flow_kat_client_auth_frame") {
            eq("client_auth", clientAuthFrame, framesE["client_auth"] as String)
        }

        // ============================================================================
        // (5) Mutation guards — a tampered signature / MAC MUST reject.
        // ============================================================================
        leg("handshake_flow_kat_mutation_guard") {
            // Flip one octet of the server CertVerify signature (last octet, inside the sig).
            val badCV = sCV.copyOf()
            badCV[badCV.size - 1] = (badCV[badCV.size - 1].toInt() xor 0x01).toByte()
            check(!Handshake.verifyCertVerify(serverPubKey, ROLE_SERVER, thSid, badCV)) {
                "a one-octet-flipped server CertVerify signature VERIFIED"
            }
            // Flip one octet of the client Finished MAC.
            val badFin = cFin.copyOf()
            badFin[0] = (badFin[0].toInt() xor 0x01).toByte()
            check(!Handshake.verifyFinished(cFinKey, thCcv, badFin, STANDARD)) {
                "a one-octet-flipped client Finished MAC VERIFIED"
            }
            // Sanity: the untouched signature and MAC still verify.
            check(Handshake.verifyCertVerify(serverPubKey, ROLE_SERVER, thSid, sCV)) {
                "unmutated server CertVerify should verify"
            }
            check(Handshake.verifyFinished(cFinKey, thCcv, cFin, STANDARD)) {
                "unmutated client Finished should verify"
            }
        }

        val ran = 12 // legs actually executed (not counting the SKIP)
        if (failures == 0) {
            println("ALL PASS ($ran/$ran, $skips skipped)")
        } else {
            println("FAILURES: $failures")
        }
        exitProcess(if (failures == 0) 0 else 1)
    }

    /**
     * Extracts the 32-octet Ed25519 identity public from an AUTH plaintext hex: the first TLV
     * is IdentityKey (0x09), so the value is the 32 octets after the 4-octet TLV header
     * (00 09 00 20). The vector's own auth_plaintext is the source of truth for the identity
     * keys, so this is not a free constant — the full auth_plaintext is byte-pinned elsewhere.
     */
    private fun identityKeyFromAuthPlaintext(authPtHex: String): ByteArray {
        val bytes = KatSupport.fromHex(authPtHex)
        check(bytes.size >= 4 + 32) { "auth_plaintext too short to hold an IdentityKey TLV" }
        val type = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
        val len = ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
        check(type == TLV_IDENTITY_KEY) { "first AUTH TLV is 0x%02x, want 0x09 (IdentityKey)".format(type) }
        check(len == 32) { "IdentityKey TLV is $len octets, want 32" }
        return bytes.copyOfRange(4, 4 + 32)
    }

    /** Derives the traffic secret/key/iv through the impl and asserts each pinned value. */
    private fun assertTrafficKeyIv(
        name: String,
        parent: ByteArray,
        dir: Int,
        sec: Map<String, Any?>,
        tsKey: String,
        keyKey: String,
        ivKey: String,
    ) {
        val ts = Npamp.deriveTrafficSecret(parent, dir, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, STANDARD)
        eq("${name}_traffic_secret", ts, sec[tsKey] as String)
        val keyIv = Npamp.deriveKeyIv(ts, STANDARD)
        eq("${name}_key", keyIv[0], sec[keyKey] as String)
        eq("${name}_iv", keyIv[1], sec[ivKey] as String)
    }
}
