// Byte-pinned handshake-flow known-answer test (issue #60, class golden-interop).
// Unlike the standards-anchored primitive KATs (transcript / key-schedule / certverify /
// finished), this vector pins the Go reference's SERIALIZED handshake frames so every
// language impl reproduces them byte-for-byte. The CLIENT_HELLO assertion below is the one
// that would have caught the draft-00-vs-draft-01 ProfileOffer wire drift (a fixed 4-octet
// ProfileOffer vs the draft-01 one-octet form). Java mirror of the Go reference verifier
// impl/go/handshakeflow_kat_test.go against the SAME pinned vector
// (test-vectors/v1/handshake-flow-kat.json).
//
// This runner rebuilds every EXPECTED artifact through THIS impl's real code path from the
// pinned INPUTS and asserts WHOLE-frame byte-equality (client_hello/server_hello/
// server_auth/client_auth), transcript points, the full spec/10 section 5 key ladder,
// Finished keys + MACs, CertVerify signatures, and the AUTH plaintexts; then mutation-guards
// (a one-octet-flipped server CertVerify signature AND client Finished MAC must REJECT).
//
// KEM leg honesty: the X25519 leg is decapsulated for REAL through the JDK XDH provider
// (client private x server public, where server public is the 32-octet tail of the pinned
// kem_ciphertext) and asserted against the pinned x25519_shared_secret. The ML-KEM leg is a
// pinned self-validating input: this impl carries no ML-KEM (JDK 21 ships none, and the
// impl is in the no-new-dependency tier), so mlkem_shared_secret is consumed from the vector
// and its structural placement (kem_ciphertext = mlkem_ciphertext || server_x25519_public)
// is asserted byte-exactly. Every other artifact is rebuilt through the impl's real crypto.
//
// Run via (from impl/java):
//   javac -d <out> src/main/java/sh/bubblefish/npamp/*.java \
//                  src/test/java/sh/bubblefish/npamp/Kat.java \
//                  src/test/java/sh/bubblefish/npamp/HandshakeFlowKat.java
//   java  -cp <out> sh.bubblefish.npamp.HandshakeFlowKat
package sh.bubblefish.npamp;

import static sh.bubblefish.npamp.Kat.fromHex;
import static sh.bubblefish.npamp.Kat.sat;
import static sh.bubblefish.npamp.Kat.toHex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

public final class HandshakeFlowKat {

    private HandshakeFlowKat() {
    }

    static final String HANDSHAKE_FLOW_KAT_SHA256 =
            "cf1d3c1fba550f3742e4de16d0f86d3beeafeb56efff90f85ff16165063c0fc9";

    // Standard profile (SHA-256, 32-octet secrets). The vector's "profile" is "Standard".
    static final boolean STANDARD = true;
    static final int PROFILE_STANDARD = 0x01; // spec/10 profile code point (Go ProfileStandard = 0x01)
    static final int X25519_PUBLIC_LEN = 32; // the tail of kem_ciphertext / kem_share

    private static int failures = 0;

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("ok   - " + name);
        } else {
            System.out.println("FAIL - " + name + (detail.isEmpty() ? "" : ": " + detail));
            failures++;
        }
    }

    private static void checkHex(String name, byte[] got, String wantHex) {
        String g = toHex(got);
        check(name, g.equals(wantHex), "got " + g + " want " + wantHex);
    }

    // -- Real X25519 decapsulation via the JDK XDH provider ----------------

    /** Builds an X25519 private key from its raw 32-octet scalar (RFC 7748). */
    private static PrivateKey x25519PrivateFromRaw(byte[] raw) {
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            return kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, raw.clone()));
        } catch (Exception e) {
            throw new RuntimeException("x25519 private from raw failed", e);
        }
    }

    /**
     * Builds an X25519 public key from its raw 32-octet little-endian u-coordinate
     * (RFC 7748 section 5): mask the high bit, reverse to big-endian, wrap as the u value.
     */
    private static PublicKey x25519PublicFromRaw(byte[] raw) {
        try {
            if (raw.length != X25519_PUBLIC_LEN) {
                throw new IllegalArgumentException("x25519 public must be 32 octets, got " + raw.length);
            }
            byte[] le = raw.clone();
            le[le.length - 1] &= 0x7F; // clear the unused high bit (u is 255 bits)
            byte[] be = new byte[le.length];
            for (int i = 0; i < le.length; i++) {
                be[i] = le[le.length - 1 - i];
            }
            BigInteger u = new BigInteger(1, be);
            KeyFactory kf = KeyFactory.getInstance("XDH");
            return kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        } catch (Exception e) {
            throw new RuntimeException("x25519 public from raw failed", e);
        }
    }

    /** Raw X25519 ECDH shared secret (32 octets), independent of any ML-KEM material. */
    private static byte[] x25519(PrivateKey priv, PublicKey pub) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("x25519 agreement failed", e);
        }
    }

    // -- Handshake wire builders (mirror the Go ClientHello/ServerHello/AuthMessage.Encode) --

    private static byte[] u16be(int v) {
        return new byte[]{(byte) ((v >>> 8) & 0xFF), (byte) (v & 0xFF)};
    }

    /** Appends one TLV: Type(2 BE) || Length(2 BE) || Value (the spec section 4 encoding). */
    private static void appendTLV(ByteArrayOutputStream buf, int type, byte[] value) {
        buf.writeBytes(u16be(type));
        buf.writeBytes(u16be(value.length));
        buf.writeBytes(value);
    }

    /**
     * CLIENT_HELLO payload (spec/10 section 1): ProfileOffer, KEMOffer, SigOffer, AEADOffer,
     * KEMShare, in that order. ProfileOffer is the draft-01 ONE-OCTET-PER-PROFILE form (a
     * single 0x01 for {Standard}); the draft-00 fixed 4-octet ProfileOffer would not match.
     */
    private static byte[] clientHelloPayload(byte[] kemShare) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        appendTLV(b, Npamp.TLV_PROFILE_OFFER, new byte[]{(byte) PROFILE_STANDARD});
        appendTLV(b, 0x03 /* KEMOffer */, u16be(Npamp.KEM_X25519_MLKEM768));
        appendTLV(b, 0x05 /* SigOffer */, u16be(Npamp.SIG_ED25519));
        appendTLV(b, 0x0C /* AEADOffer */, u16be(Npamp.AEAD_AES256_GCM));
        appendTLV(b, 0x07 /* KEMShare */, kemShare);
        return b.toByteArray();
    }

    /**
     * SERVER_HELLO payload (spec/10 section 1): ProfileSelect (1 octet), KEMSelect,
     * SigSelect, AEADSelect (2 octets each), KEMCiphertext, in that order.
     */
    private static byte[] serverHelloPayload(byte[] kemCiphertext) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        appendTLV(b, 0x02 /* ProfileSelect */, new byte[]{(byte) PROFILE_STANDARD});
        appendTLV(b, 0x04 /* KEMSelect */, u16be(Npamp.KEM_X25519_MLKEM768));
        appendTLV(b, 0x06 /* SigSelect */, u16be(Npamp.SIG_ED25519));
        appendTLV(b, 0x0D /* AEADSelect */, u16be(Npamp.AEAD_AES256_GCM));
        appendTLV(b, 0x08 /* KEMCiphertext */, kemCiphertext);
        return b.toByteArray();
    }

    /** AUTH plaintext (spec/10 section 6.4): IdentityKey, CertVerify, Finished TLVs, in order. */
    private static byte[] authPlaintext(byte[] identityKey, byte[] certVerify, byte[] finished) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        appendTLV(b, 0x09 /* IdentityKey */, identityKey);
        appendTLV(b, 0x0A /* CertVerify */, certVerify);
        appendTLV(b, 0x0B /* Finished */, finished);
        return b.toByteArray();
    }

    /** Serializes a cleartext handshake frame (Control channel, seq 0) via the real record path. */
    private static byte[] marshalCleartextFrame(int frameType, byte[] payload) {
        Npamp.Frame f = new Npamp.Frame(frameType, Npamp.CHAN_CONTROL, 0L, 0, 0, payload);
        return f.marshal();
    }

    /**
     * Seals an AUTH plaintext into a wire frame through the impl's real key-schedule + record
     * path: derive traffic secret from the direction's handshake secret, derive key/iv, then
     * AEAD-seal under the 21-octet header prefix and marshal the FLAG_ENC frame (mirrors the
     * Go sealAuthKAT).
     */
    private static byte[] sealAuthFrame(int frameType, byte[] baseSecret, int dir, byte[] plaintext) {
        byte[] ts = Npamp.deriveTrafficSecret(baseSecret, dir, 0L,
                Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, STANDARD);
        byte[][] keyIv = Npamp.deriveKeyIv(ts, STANDARD);
        Npamp.Frame f = new Npamp.Frame(frameType, Npamp.CHAN_CONTROL, 0L, Npamp.FLAG_ENC, 0, new byte[0]);
        byte[] aad = f.headerPrefix(plaintext.length + 16); // +16 = the GCM tag
        byte[] sealed = Npamp.sealAes256Gcm(keyIv[0], keyIv[1], 0L, aad, plaintext);
        f.payload = sealed;
        return f.marshal();
    }

    // -- Directions (mirror the Go DirClientToServer / DirServerToClient) --
    static final int DIR_CLIENT_TO_SERVER = 0x00;
    static final int DIR_SERVER_TO_CLIENT = 0x01;

    public static void main(String[] args) throws Exception {
        Object root = Kat.loadPinned(args, "handshake-flow-kat.json", HANDSHAKE_FLOW_KAT_SHA256);

        // --- Pinned inputs ---
        byte[] clientX25519Priv = fromHex(sat(root, "inputs", "client_x25519_private"));
        byte[] mlkemCiphertext = fromHex(sat(root, "inputs", "mlkem_ciphertext"));
        byte[] clientEdSeed = fromHex(sat(root, "inputs", "client_identity_ed25519_seed"));
        byte[] serverEdSeed = fromHex(sat(root, "inputs", "server_identity_ed25519_seed"));
        byte[] wantMlkemSs = fromHex(sat(root, "inputs", "mlkem_shared_secret"));
        byte[] wantX25519Ss = fromHex(sat(root, "inputs", "x25519_shared_secret"));
        byte[] wantCombined = fromHex(sat(root, "inputs", "combined_secret"));

        // --- Long-term Ed25519 identities from the fixed seeds (deterministic pubkeys) ---
        PrivateKey clientEdPriv = Handshake.ed25519PrivateKeyFromSeed(clientEdSeed);
        PrivateKey serverEdPriv = Handshake.ed25519PrivateKeyFromSeed(serverEdSeed);
        byte[] clientPub = ed25519RawPublic(clientEdSeed);
        byte[] serverPub = ed25519RawPublic(serverEdSeed);
        PublicKey clientPubKey = Handshake.ed25519PublicKeyFromRaw(clientPub);
        PublicKey serverPubKey = Handshake.ed25519PublicKeyFromRaw(serverPub);

        // --- KEM wire structure + REAL X25519 decapsulation ---
        // The pinned kem_ciphertext = ml-kem ciphertext || server X25519 public.
        byte[] kemCiphertext = fromHex(sat(root, "expected", "kem", "kem_ciphertext"));
        byte[] kemShare = fromHex(sat(root, "expected", "kem", "kem_share"));
        byte[] ctFront = Arrays.copyOfRange(kemCiphertext, 0, kemCiphertext.length - X25519_PUBLIC_LEN);
        byte[] serverX25519Pub = Arrays.copyOfRange(kemCiphertext, kemCiphertext.length - X25519_PUBLIC_LEN, kemCiphertext.length);
        check("kem: kem_ciphertext front == pinned mlkem_ciphertext input",
                Arrays.equals(ctFront, mlkemCiphertext), "");
        // The KEMShare tail is the CLIENT X25519 public; assert it is 32 octets present.
        byte[] clientX25519Pub = Arrays.copyOfRange(kemShare, kemShare.length - X25519_PUBLIC_LEN, kemShare.length);
        check("kem: kem_share carries a 32-octet X25519 tail",
                clientX25519Pub.length == X25519_PUBLIC_LEN, "");

        // REAL X25519 leg: client_priv x server_pub must recover the pinned x25519_shared_secret.
        byte[] x25519Ss = x25519(x25519PrivateFromRaw(clientX25519Priv), x25519PublicFromRaw(serverX25519Pub));
        checkHex("kem: X25519 decapsulation recovers x25519_shared_secret",
                x25519Ss, sat(root, "inputs", "x25519_shared_secret"));

        // ML-KEM leg: JDK 21 ships no ML-KEM (this impl is no-new-dep tier), so the ML-KEM
        // shared secret is the pinned self-validating input. Combine ML-KEM-first (ADR-0005).
        byte[] combined = new byte[wantMlkemSs.length + x25519Ss.length];
        System.arraycopy(wantMlkemSs, 0, combined, 0, wantMlkemSs.length);
        System.arraycopy(x25519Ss, 0, combined, wantMlkemSs.length, x25519Ss.length);
        checkHex("kem: combined_secret == ml-kem_ss || x25519_ss", combined, sat(root, "inputs", "combined_secret"));
        check("kem: pinned combined_secret is internally consistent",
                Arrays.equals(combined, wantCombined) && Arrays.equals(x25519Ss, wantX25519Ss), "");

        // --- CLIENT_HELLO whole-frame byte-equality (the ProfileOffer wire-drift guard) ---
        byte[] chPayload = clientHelloPayload(kemShare);
        byte[] chFrame = marshalCleartextFrame(Handshake.FRAME_CLIENT_HELLO, chPayload);
        checkHex("frame: client_hello (whole frame)", chFrame, sat(root, "expected", "frames", "client_hello"));

        // --- SERVER_HELLO whole-frame byte-equality ---
        byte[] shPayload = serverHelloPayload(kemCiphertext);
        byte[] shFrame = marshalCleartextFrame(Handshake.FRAME_SERVER_HELLO, shPayload);
        checkHex("frame: server_hello (whole frame)", shFrame, sat(root, "expected", "frames", "server_hello"));

        // --- Transcript + key ladder through the REAL impl ---
        Handshake.Transcript tr = new Handshake.Transcript();
        // CLIENT_HELLO: frame type then its five TLVs, in wire order.
        tr.addFrameType(Handshake.FRAME_CLIENT_HELLO);
        tr.addTLV(Npamp.TLV_PROFILE_OFFER, new byte[]{(byte) PROFILE_STANDARD});
        tr.addTLV(0x03, u16be(Npamp.KEM_X25519_MLKEM768));
        tr.addTLV(0x05, u16be(Npamp.SIG_ED25519));
        tr.addTLV(0x0C, u16be(Npamp.AEAD_AES256_GCM));
        tr.addTLV(0x07, kemShare);
        // SERVER_HELLO: frame type then its five TLVs.
        tr.addFrameType(Handshake.FRAME_SERVER_HELLO);
        tr.addTLV(0x02, new byte[]{(byte) PROFILE_STANDARD});
        tr.addTLV(0x04, u16be(Npamp.KEM_X25519_MLKEM768));
        tr.addTLV(0x06, u16be(Npamp.SIG_ED25519));
        tr.addTLV(0x0D, u16be(Npamp.AEAD_AES256_GCM));
        tr.addTLV(0x08, kemCiphertext);
        byte[] thKem = tr.hash(STANDARD);
        checkHex("transcript: th_kem", thKem, sat(root, "expected", "transcript", "th_kem"));

        // handshake_secret = HKDF-Extract(0-salt, ML-KEM_SS || X25519_SS).
        byte[] hs = Handshake.deriveHandshakeSecret(wantMlkemSs, x25519Ss, STANDARD);
        checkHex("secret: handshake_secret", hs, sat(root, "expected", "secrets", "handshake_secret"));
        byte[] cHS = Handshake.deriveClientHandshakeSecret(hs, thKem, STANDARD);
        byte[] sHS = Handshake.deriveServerHandshakeSecret(hs, thKem, STANDARD);
        checkHex("secret: c_hs_secret", cHS, sat(root, "expected", "secrets", "c_hs_secret"));
        checkHex("secret: s_hs_secret", sHS, sat(root, "expected", "secrets", "s_hs_secret"));

        // --- SERVER_AUTH: IdentityKey, then TH_sId, CertVerify, TH_sCV, Finished ---
        tr.addFrameType(Handshake.FRAME_SERVER_AUTH);
        tr.addTLV(0x09, serverPub);
        byte[] thSID = tr.hash(STANDARD);
        checkHex("transcript: th_sid", thSID, sat(root, "expected", "transcript", "th_sid"));
        byte[] sCV = Handshake.signCertVerify(serverEdPriv, true, thSID);
        checkHex("certverify: server", sCV, sat(root, "expected", "cert_verify", "server"));
        check("certverify: server verifies", Handshake.verifyCertVerify(serverPubKey, true, thSID, sCV), "");
        tr.addTLV(0x0A, sCV);
        byte[] thSCV = tr.hash(STANDARD);
        checkHex("transcript: th_scv", thSCV, sat(root, "expected", "transcript", "th_scv"));
        byte[] sFinKey = Handshake.deriveFinishedKey(sHS, STANDARD);
        checkHex("finished_key: server", sFinKey, sat(root, "expected", "finished_keys", "server"));
        byte[] sFin = Handshake.computeFinished(sFinKey, thSCV, STANDARD);
        checkHex("finished: server", sFin, sat(root, "expected", "finished", "server"));
        tr.addTLV(0x0B, sFin);
        byte[] serverAuthPlain = authPlaintext(serverPub, sCV, sFin);
        checkHex("auth_plaintext: server_auth", serverAuthPlain, sat(root, "expected", "auth_plaintext", "server_auth"));
        byte[] serverAuthFrame = sealAuthFrame(Handshake.FRAME_SERVER_AUTH, sHS, DIR_SERVER_TO_CLIENT, serverAuthPlain);
        checkHex("frame: server_auth (whole frame)", serverAuthFrame, sat(root, "expected", "frames", "server_auth"));

        // --- CLIENT_AUTH: IdentityKey, then TH_cId, CertVerify, TH_cCV, Finished ---
        tr.addFrameType(Handshake.FRAME_CLIENT_AUTH);
        tr.addTLV(0x09, clientPub);
        byte[] thCID = tr.hash(STANDARD);
        checkHex("transcript: th_cid", thCID, sat(root, "expected", "transcript", "th_cid"));
        byte[] cCV = Handshake.signCertVerify(clientEdPriv, false, thCID);
        checkHex("certverify: client", cCV, sat(root, "expected", "cert_verify", "client"));
        check("certverify: client verifies", Handshake.verifyCertVerify(clientPubKey, false, thCID, cCV), "");
        tr.addTLV(0x0A, cCV);
        byte[] thCCV = tr.hash(STANDARD);
        checkHex("transcript: th_ccv", thCCV, sat(root, "expected", "transcript", "th_ccv"));
        byte[] cFinKey = Handshake.deriveFinishedKey(cHS, STANDARD);
        checkHex("finished_key: client", cFinKey, sat(root, "expected", "finished_keys", "client"));
        byte[] cFin = Handshake.computeFinished(cFinKey, thCCV, STANDARD);
        checkHex("finished: client", cFin, sat(root, "expected", "finished", "client"));
        byte[] clientAuthPlain = authPlaintext(clientPub, cCV, cFin);
        checkHex("auth_plaintext: client_auth", clientAuthPlain, sat(root, "expected", "auth_plaintext", "client_auth"));
        byte[] clientAuthFrame = sealAuthFrame(Handshake.FRAME_CLIENT_AUTH, cHS, DIR_CLIENT_TO_SERVER, clientAuthPlain);
        checkHex("frame: client_auth (whole frame)", clientAuthFrame, sat(root, "expected", "frames", "client_auth"));

        // --- Master secret + application-phase traffic keys ---
        byte[] master = Handshake.deriveMasterSecret(hs, thCCV, STANDARD);
        checkHex("secret: master_secret", master, sat(root, "expected", "secrets", "master_secret"));

        checkTrafficKeyIv(root, "c_hs", cHS, DIR_CLIENT_TO_SERVER);
        checkTrafficKeyIv(root, "s_hs", sHS, DIR_SERVER_TO_CLIENT);
        checkTrafficKeyIv(root, "app_c2s", master, DIR_CLIENT_TO_SERVER);
        checkTrafficKeyIv(root, "app_s2c", master, DIR_SERVER_TO_CLIENT);

        // --- Mutation guard 1: a one-octet flip in the server CertVerify signature must REJECT. ---
        byte[] badCV = sCV.clone();
        badCV[badCV.length - 1] ^= 0x01; // flip a signature bit (last octet of the Ed25519 sig)
        check("mutation: flipped server CertVerify signature REJECTS",
                !Handshake.verifyCertVerify(serverPubKey, true, thSID, badCV), "");

        // --- Mutation guard 2: a one-octet flip in the client Finished MAC must REJECT. ---
        byte[] badFin = cFin.clone();
        badFin[0] ^= 0x01;
        check("mutation: flipped client Finished MAC REJECTS",
                !Handshake.verifyFinished(cFinKey, thCCV, badFin, STANDARD), "");

        // --- Sanity: the untouched signature and MAC still verify. ---
        check("sanity: unmutated server CertVerify verifies",
                Handshake.verifyCertVerify(serverPubKey, true, thSID, sCV), "");
        check("sanity: unmutated client Finished verifies",
                Handshake.verifyFinished(cFinKey, thCCV, cFin, STANDARD), "");

        System.out.println(failures == 0
                ? "ALL PASS (handshake-flow KAT: frames+transcript+ladder+auth+mutation-guard)"
                : ("FAILURES: " + failures));
        System.exit(failures == 0 ? 0 : 1);
    }

    /** Derives the traffic secret/key/iv through the impl and asserts each against the vector. */
    private static void checkTrafficKeyIv(Object root, String name, byte[] parent, int dir) {
        byte[] ts = Npamp.deriveTrafficSecret(parent, dir, 0L, Npamp.AEAD_AES256_GCM, Npamp.CHAN_CONTROL, STANDARD);
        checkHex("secret: " + name + "_traffic_secret", ts, sat(root, "expected", "secrets", name + "_traffic_secret"));
        byte[][] keyIv = Npamp.deriveKeyIv(ts, STANDARD);
        checkHex("secret: " + name + "_key", keyIv[0], sat(root, "expected", "secrets", name + "_key"));
        checkHex("secret: " + name + "_iv", keyIv[1], sat(root, "expected", "secrets", name + "_iv"));
    }

    // -- RFC 8032 Ed25519 public-key derivation from a seed --------------------
    //
    // The JDK exposes no API to recover a raw public key from a seed-derived private key, and
    // the vector does not pin the identity public keys separately. This test therefore derives
    // A = clamp(SHA-512(seed)[:32]) . B and encodes it per RFC 8032 section 5.1.5 — a real,
    // non-circular derivation. verifyCertVerify below then proves the derived public key
    // matches the private key that produced each pinned signature.

    private static final BigInteger ED_P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger ED_D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(ED_P)).mod(ED_P);
    private static final BigInteger ED_BY = BigInteger.valueOf(4)
            .multiply(BigInteger.valueOf(5).modInverse(ED_P)).mod(ED_P);
    private static final BigInteger[] ED_B = {recoverX(ED_BY), ED_BY};

    private static BigInteger recoverX(BigInteger y) {
        BigInteger y2 = y.multiply(y).mod(ED_P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(ED_P);
        BigInteger v = ED_D.multiply(y2).add(BigInteger.ONE).mod(ED_P);
        BigInteger uv3 = u.multiply(v.modPow(BigInteger.valueOf(3), ED_P)).mod(ED_P);
        BigInteger uv7 = u.multiply(v.modPow(BigInteger.valueOf(7), ED_P)).mod(ED_P);
        BigInteger x = uv3.multiply(uv7.modPow(
                ED_P.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8)), ED_P)).mod(ED_P);
        BigInteger vx2 = v.multiply(x).multiply(x).mod(ED_P);
        if (!vx2.equals(u.mod(ED_P)) && vx2.equals(u.negate().mod(ED_P))) {
            x = x.multiply(BigInteger.TWO.modPow(
                    ED_P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), ED_P)).mod(ED_P);
        }
        // The basepoint's x is even; normalize to the canonical sign.
        return x.testBit(0) ? ED_P.subtract(x) : x;
    }

    private static BigInteger[] edwardsAdd(BigInteger[] p, BigInteger[] q) {
        BigInteger x1 = p[0], y1 = p[1], x2 = q[0], y2 = q[1];
        BigInteger dxy = ED_D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(ED_P);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1))
                .multiply(BigInteger.ONE.add(dxy).modInverse(ED_P)).mod(ED_P);
        BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2))
                .multiply(BigInteger.ONE.subtract(dxy).modInverse(ED_P)).mod(ED_P);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] edwardsScalarMul(BigInteger[] point, BigInteger e) {
        BigInteger[] r = {BigInteger.ZERO, BigInteger.ONE};
        BigInteger[] q = point;
        while (e.signum() > 0) {
            if (e.testBit(0)) {
                r = edwardsAdd(r, q);
            }
            q = edwardsAdd(q, q);
            e = e.shiftRight(1);
        }
        return r;
    }

    /** Encodes an Edwards point as 32 little-endian octets with the x-sign in the high bit. */
    private static byte[] encodePoint(BigInteger[] point) {
        byte[] out = new byte[32];
        byte[] yb = point[1].toByteArray();
        for (int i = 0; i < yb.length && i < 32; i++) {
            out[i] = yb[yb.length - 1 - i];
        }
        if (point[0].testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    /** Derives the raw 32-octet Ed25519 public key from a seed (RFC 8032 section 5.1.5). */
    private static byte[] ed25519RawPublic(byte[] seed) {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-512").digest(seed);
            byte[] a = Arrays.copyOfRange(h, 0, 32);
            a[0] &= (byte) 248;
            a[31] &= (byte) 127;
            a[31] |= (byte) 64;
            byte[] be = new byte[32];
            for (int i = 0; i < 32; i++) {
                be[i] = a[31 - i];
            }
            BigInteger s = new BigInteger(1, be);
            return encodePoint(edwardsScalarMul(ED_B, s));
        } catch (Exception e) {
            throw new RuntimeException("ed25519 public from seed failed", e);
        }
    }
}
