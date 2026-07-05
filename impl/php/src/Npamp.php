<?php

/**
 * Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
 *
 * OPEN protocol layer only: framing, registries, the AEAD record layer, and the
 * HKDF-Expand-Label key schedule. No proprietary methods, parameters, or weights.
 *
 * Port of the Python reference (impl/python/npamp/__init__.py). Big-endian
 * throughout; matches the Go/Java/Python/C# reference implementations byte-for-byte.
 */

declare(strict_types=1);

namespace Sh\Bubblefish\Npamp;

/**
 * Raised when a frame fails to unmarshal (short header, bad CRC, bad magic,
 * bad version, reserved-nonzero, or length mismatch).
 */
final class FrameException extends \RuntimeException
{
}

/**
 * Raised when an AEAD open (decrypt) is rejected: authentication failure,
 * truncated tag, or any input the cipher will not accept.
 */
final class AeadException extends \RuntimeException
{
}

final class Npamp
{
    public const HEADER_SIZE = 36;
    public const PROTOCOL_VERSION = 0x2;
    public const MAGIC = "NPAM";
    public const ALPN = "n-pamp/2";
    /** Protocol-specific HKDF label prefix; NOT "tls13 ". Note the trailing space. */
    public const LABEL_PREFIX = "n-pamp ";

    public const FLAG_URG = 0x01;
    public const FLAG_ENC = 0x02;
    public const FLAG_COMP = 0x04;
    public const FLAG_FRAG = 0x08;

    public const CHAN_CONTROL = 0x0000;
    public const CHAN_MEMORY = 0x0001;
    public const CHAN_IMMUNE = 0x0005;
    public const CHAN_AUDIT = 0x000B;
    public const CHAN_BRIDGE = 0x000D;
    public const CHAN_SPATIAL = 0x0013;

    public const FRAME_PING = 0x0001;
    public const FRAME_PONG = 0x0002;
    public const FRAME_CLOSE = 0x0003;
    public const FRAME_FLOW_UPDATE = 0x000A;
    public const CHANNEL_SPECIFIC_BASE = 0x0100;

    public const TLV_PROFILE_OFFER = 0x01;
    public const TLV_KEM_CIPHERTEXT = 0x08;
    public const TLV_ANOMALY_CHARGE = 0x12;

    public const KEM_X25519_MLKEM768 = 0x11ec;
    public const KEM_X25519_MLKEM1024 = 0x11ed;

    public const AEAD_AES256_GCM = 0x0001;
    public const AEAD_CHACHA20_POLY1305 = 0x0002;

    public const SIG_ED25519 = 0x0807;
    public const SIG_MLDSA87 = 0x0905;

    /**
     * CRC32C (Castagnoli, reflected) - identical to Go hash/crc32 Castagnoli.
     *
     * poly 0x82F63B78, init 0xFFFFFFFF, final-xor 0xFFFFFFFF. All intermediate
     * arithmetic is masked to 32 bits so this is correct on 64-bit PHP. PHP's
     * built-in crc32()/hash("crc32b") compute the IEEE polynomial and MUST NOT
     * be used here.
     *
     * @return int unsigned 32-bit CRC (0 .. 0xFFFFFFFF)
     */
    public static function crc32c(string $data): int
    {
        $poly = 0x82F63B78;
        $crc = 0xFFFFFFFF;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $crc ^= ord($data[$i]);
            $crc &= 0xFFFFFFFF;
            for ($k = 0; $k < 8; $k++) {
                if ($crc & 1) {
                    $crc = (($crc >> 1) ^ $poly) & 0xFFFFFFFF;
                } else {
                    $crc = ($crc >> 1) & 0xFFFFFFFF;
                }
            }
        }
        return ($crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
    }

    /**
     * Encode an unsigned integer as a big-endian byte string of the given width.
     * Width must be 1..8 (the protocol uses u8/u16/u32/u64 fields).
     */
    public static function uintToBytes(int $value, int $width): string
    {
        $out = '';
        for ($i = $width - 1; $i >= 0; $i--) {
            $out .= chr(($value >> ($i * 8)) & 0xFF);
        }
        return $out;
    }

    /**
     * Decode a big-endian byte string (of width 1..8) into an unsigned integer.
     */
    public static function bytesToUint(string $data): int
    {
        $value = 0;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $value = ($value << 8) | ord($data[$i]);
        }
        return $value;
    }

    public static function toHex(string $data): string
    {
        return bin2hex($data);
    }

    /**
     * Per-frame AEAD nonce (draft-00 7.5): IV XOR left-zero-padded seq. No channel.
     *
     * The seq (u64 big-endian) is placed in bytes[4..12] of a 12-byte zero buffer,
     * then XORed with the 12-byte IV. With seq=0 the nonce equals the IV.
     */
    public static function deriveNonce(string $iv, int $seq): string
    {
        if (strlen($iv) !== 12) {
            throw new \InvalidArgumentException('iv must be 12 bytes');
        }
        $n = str_repeat("\0", 4) . self::uintToBytes($seq, 8);
        $out = '';
        for ($i = 0; $i < 12; $i++) {
            $out .= chr(ord($n[$i]) ^ ord($iv[$i]));
        }
        return $out;
    }

    /**
     * AES-256-GCM seal. Returns ciphertext || tag (16-byte GCM tag).
     * The 21-byte header prefix is the AAD.
     */
    public static function sealAes256Gcm(string $key, string $iv, int $seq, string $aad, string $pt): string
    {
        $nonce = self::deriveNonce($iv, $seq);
        $tag = '';
        $ct = openssl_encrypt($pt, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
        if ($ct === false) {
            throw new AeadException('aes-256-gcm seal failed');
        }
        return $ct . $tag;
    }

    /**
     * AES-256-GCM open. Splits sealed into ciphertext || 16-byte tag, verifies and
     * decrypts. Throws AeadException on any authentication failure or malformed input
     * (e.g. truncated tag), so callers reject exactly the inputs the cipher rejects.
     */
    public static function openAes256Gcm(string $key, string $iv, int $seq, string $aad, string $sealed): string
    {
        if (strlen($sealed) < 16) {
            throw new AeadException('sealed shorter than tag');
        }
        $nonce = self::deriveNonce($iv, $seq);
        $ct = substr($sealed, 0, strlen($sealed) - 16);
        $tag = substr($sealed, strlen($sealed) - 16, 16);
        $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($pt === false) {
            throw new AeadException('aes-256-gcm authentication failed');
        }
        return $pt;
    }

    /**
     * HKDF-Expand-Label (RFC 5869 sec 2.3, Expand only; PRK = the given secret,
     * NO extract step). The protocol prefix is "n-pamp " (NOT "tls13 ").
     *
     * info = u16(length) | u8(len(full)) | full | u8(len(context)) | context
     * where full = LABEL_PREFIX . label (ASCII).
     * Hash is SHA-256 when $standard is true, SHA-384 when false (the "high" profile).
     */
    public static function hkdfExpandLabel(string $secret, string $label, string $context, int $length, bool $standard): string
    {
        $full = self::LABEL_PREFIX . $label;
        $info = self::uintToBytes($length, 2)
            . chr(strlen($full)) . $full
            . chr(strlen($context)) . $context;
        $algo = $standard ? 'sha256' : 'sha384';
        return self::hkdfExpand($secret, $info, $length, $algo);
    }

    /**
     * RFC 5869 section 2.3 HKDF-Expand. PRK is the provided secret (no extract step).
     *
     * T(0) = empty; T(n) = HMAC-Hash(PRK, T(n-1) | info | n). OKM = first $length
     * octets of T(1) | T(2) | ...
     */
    private static function hkdfExpand(string $prk, string $info, int $length, string $algo): string
    {
        $hashLen = strlen(hash_hmac($algo, '', $prk, true));
        $n = intdiv($length + $hashLen - 1, $hashLen);
        if ($n > 255) {
            throw new \InvalidArgumentException('HKDF-Expand: length too large');
        }
        $okm = '';
        $t = '';
        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac($algo, $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }
        return substr($okm, 0, $length);
    }

    /**
     * Derive a traffic secret (draft-00 key schedule).
     *
     * context = dir(1) | epoch(8 BE) | suite(2 BE) | channel(2 BE); label "traffic";
     * output 32 octets (SHA-256, standard) or 48 octets (SHA-384, high).
     */
    public static function deriveTrafficSecret(string $master, int $direction, int $epoch, int $suite, int $channel, bool $standard): string
    {
        $ctx = chr($direction & 0xFF)
            . self::uintToBytes($epoch, 8)
            . self::uintToBytes($suite, 2)
            . self::uintToBytes($channel, 2);
        $hlen = $standard ? 32 : 48;
        return self::hkdfExpandLabel($master, 'traffic', $ctx, $hlen, $standard);
    }

    /**
     * Derive the record-layer key (32 octets) and IV (12 octets) from a traffic secret.
     *
     * @return array{0:string,1:string} [key, iv]
     */
    public static function deriveKeyIv(string $secret, bool $standard): array
    {
        return [
            self::hkdfExpandLabel($secret, 'key', '', 32, $standard),
            self::hkdfExpandLabel($secret, 'iv', '', 12, $standard),
        ];
    }

    /**
     * HKDF-Extract (RFC 5869 sec 2.2): PRK = HMAC-Hash(salt, IKM).
     *
     * The salt is the HMAC key; the IKM (input keying material) is the HMAC
     * message. Hash is SHA-256 when $standard is true, SHA-384 when false (the
     * "high" profile), wired the same way as the rest of the key schedule.
     */
    public static function hkdfExtract(string $salt, string $ikm, bool $standard): string
    {
        return hash_hmac($standard ? 'sha256' : 'sha384', $ikm, $salt, true);
    }

    /**
     * Derive the handshake secret from the two KEM shared secrets (binding
     * spec/10 sec 5; ML-KEM-first per ADR-0005).
     *
     * IKM = ML-KEM shared secret || X25519 shared secret (the ML-KEM shared
     * secret is concatenated FIRST). The binding's default salt is HashLen zero
     * octets (32 at Standard/SHA-256). Returns HKDF-Extract(salt, IKM).
     */
    public static function deriveHandshakeSecret(string $mlkemSharedSecret, string $x25519SharedSecret, bool $standard): string
    {
        $ikm = $mlkemSharedSecret . $x25519SharedSecret;
        $salt = str_repeat("\0", $standard ? 32 : 48);
        return self::hkdfExtract($salt, $ikm, $standard);
    }

    /**
     * Client handshake-traffic secret (binding spec/10 sec 5):
     * c_hs = HKDF-Expand-Label(handshake_secret, "c hs", th_kem, HashLen).
     * Context is the KEM-phase transcript hash; output is 32 octets at Standard.
     */
    public static function deriveClientHandshakeSecret(string $handshakeSecret, string $thKem, bool $standard): string
    {
        return self::hkdfExpandLabel($handshakeSecret, 'c hs', $thKem, $standard ? 32 : 48, $standard);
    }

    /**
     * Server handshake-traffic secret (binding spec/10 sec 5):
     * s_hs = HKDF-Expand-Label(handshake_secret, "s hs", th_kem, HashLen).
     */
    public static function deriveServerHandshakeSecret(string $handshakeSecret, string $thKem, bool $standard): string
    {
        return self::hkdfExpandLabel($handshakeSecret, 's hs', $thKem, $standard ? 32 : 48, $standard);
    }

    /**
     * Master secret (binding spec/10 sec 5):
     * master = HKDF-Expand-Label(handshake_secret, "master", th_ccv, HashLen).
     * Context is the client-CertVerify-point transcript hash.
     */
    public static function deriveMasterSecret(string $handshakeSecret, string $thCcv, bool $standard): string
    {
        return self::hkdfExpandLabel($handshakeSecret, 'master', $thCcv, $standard ? 32 : 48, $standard);
    }

    /**
     * Finished key (binding spec/10 sec 6.2/5.4):
     * finished_key = HKDF-Expand-Label(secret, "finished", empty context, HashLen).
     * The client Finished key derives from c_hs; the server Finished key derives
     * from s_hs.
     */
    public static function deriveFinishedKey(string $secret, bool $standard): string
    {
        return self::hkdfExpandLabel($secret, 'finished', '', $standard ? 32 : 48, $standard);
    }
}

/**
 * A single N-PAMP frame.
 *
 * 36-byte header = prefix(21) | u32 crc32c(prefix) | 11 reserved zero octets,
 * followed by the payload. The prefix is the AEAD AAD.
 */
final class Frame
{
    public int $version;
    public int $flags;
    public int $ftype;
    public int $channel;
    public int $seq;
    public string $payload;

    public function __construct(int $ftype = 0, int $channel = 0, int $seq = 0, int $flags = 0, int $version = 0, string $payload = '')
    {
        $this->ftype = $ftype;
        $this->channel = $channel;
        $this->seq = $seq;
        $this->flags = $flags;
        $this->version = $version;
        $this->payload = $payload;
    }

    /**
     * The 21-octet header prefix:
     * MAGIC(4) | byte4=((version||2)<<4)|(flags&0x0F) | u16 ftype | u16 channel
     *          | u64 seq | u32 payloadLen.
     */
    public function headerPrefix(int $payloadLen): string
    {
        $ver = $this->version !== 0 ? $this->version : Npamp::PROTOCOL_VERSION;
        $out = Npamp::MAGIC;
        $out .= chr((($ver << 4) | ($this->flags & 0x0F)) & 0xFF);
        $out .= Npamp::uintToBytes($this->ftype, 2);
        $out .= Npamp::uintToBytes($this->channel, 2);
        $out .= Npamp::uintToBytes($this->seq, 8);
        $out .= Npamp::uintToBytes($payloadLen, 4);
        return $out;
    }

    /**
     * Serialize the full frame: prefix | crc32c(prefix) | 11 zero octets | payload.
     */
    public function marshal(): string
    {
        $prefix = $this->headerPrefix(strlen($this->payload));
        $out = $prefix;
        $out .= Npamp::uintToBytes(Npamp::crc32c($prefix), 4);
        $out .= str_repeat("\0", Npamp::HEADER_SIZE - 25); // octets 25..36 reserved, zero
        $out .= $this->payload;
        return $out;
    }

    /**
     * Parse a full frame. CRC is validated FIRST (before any field is trusted),
     * then magic, version, reserved-zero, and payload-length consistency.
     *
     * @throws FrameException on any malformed input.
     */
    public static function unmarshal(string $buf): Frame
    {
        if (strlen($buf) < Npamp::HEADER_SIZE) {
            throw new FrameException('short header');
        }
        $prefix = substr($buf, 0, 21);
        $got = Npamp::bytesToUint(substr($buf, 21, 4));
        if ($got !== Npamp::crc32c($prefix)) {
            throw new FrameException('bad crc');
        }
        if (substr($buf, 0, 4) !== Npamp::MAGIC) {
            throw new FrameException('bad magic');
        }
        $ver = ord($buf[4]) >> 4;
        if ($ver !== Npamp::PROTOCOL_VERSION) {
            throw new FrameException('bad version');
        }
        for ($i = 25; $i < Npamp::HEADER_SIZE; $i++) {
            if ($buf[$i] !== "\0") {
                throw new FrameException('reserved nonzero');
            }
        }
        $plen = Npamp::bytesToUint(substr($buf, 17, 4));
        if ($plen !== strlen($buf) - Npamp::HEADER_SIZE) {
            throw new FrameException('length mismatch');
        }
        return new Frame(
            Npamp::bytesToUint(substr($buf, 5, 2)),
            Npamp::bytesToUint(substr($buf, 7, 2)),
            Npamp::bytesToUint(substr($buf, 9, 8)),
            ord($buf[4]) & 0x0F,
            $ver,
            substr($buf, Npamp::HEADER_SIZE)
        );
    }
}

// ---------------------------------------------------------------------------
// Handshake binding layer (draft-00 binding spec/10): transcript, Finished,
// CertVerify. Port of the Python reference (npamp/__init__.py handshake layer).
// ---------------------------------------------------------------------------

/**
 * Accumulates the draft-00 handshake transcript (binding spec/10 section 3) and
 * hashes it at a cut point.
 *
 * Per-TLV granularity: addFrameType appends the 2-octet frame type ONLY (not the
 * rest of the 36-octet header - the spec section 3/7.1 divergence from RFC 8446
 * section 4.4.1); addTlv appends Type(2 BE) | Length(2 BE) | Value. A point =
 * hash over all bytes absorbed so far (SHA-256 at Standard, SHA-384 at
 * High/Sovereign).
 */
final class Transcript
{
    private string $buf = '';

    /** Absorb a frame type as exactly two big-endian octets. */
    public function addFrameType(int $ft): void
    {
        $this->buf .= Npamp::uintToBytes($ft & 0xFFFF, 2);
    }

    /** Absorb one TLV: Type(2 BE) | Length(2 BE) | Value. */
    public function addTlv(int $type, string $value): void
    {
        $this->buf .= Npamp::uintToBytes($type & 0xFFFF, 2)
            . Npamp::uintToBytes(strlen($value), 2)
            . $value;
    }

    /**
     * Hash over all bytes absorbed so far: SHA-256 when $standard is true,
     * SHA-384 when false. Returns raw (binary) digest.
     */
    public function hash(bool $standard): string
    {
        return hash($standard ? 'sha256' : 'sha384', $this->buf, true);
    }
}

/**
 * Finished MAC and CertVerify signature/verification (binding spec/10
 * sections 6.1/6.2). Ed25519 is provided by ext-sodium (bundled with PHP);
 * Finished uses hash_hmac, matching the AEAD/key-schedule layer's stdlib crypto.
 */
final class Handshake
{
    /** Handshake frame types (spec section 1), carried on the control channel. */
    public const FRAME_CLIENT_HELLO = 0x0100;
    public const FRAME_SERVER_HELLO = 0x0101;
    public const FRAME_SERVER_AUTH = 0x0102;
    public const FRAME_CLIENT_AUTH = 0x0103;

    /** CertVerify role context strings (spec section 6.1). */
    public const CONTEXT_SERVER_CERTVERIFY = 'N-PAMP draft-00, server CertificateVerify';
    public const CONTEXT_CLIENT_CERTVERIFY = 'N-PAMP draft-00, client CertificateVerify';

    /**
     * Finished (binding spec/10 section 6.2; RFC 8446 section 4.4.4):
     * verify_data = HMAC(finished_key, transcript_hash) under the profile hash
     * (SHA-256 at Standard, SHA-384 at High/Sovereign). Returns raw bytes.
     */
    public static function computeFinished(string $finishedKey, string $transcriptHash, bool $standard): string
    {
        return hash_hmac($standard ? 'sha256' : 'sha384', $transcriptHash, $finishedKey, true);
    }

    /**
     * Recompute the Finished MAC and constant-time-compare it to the received
     * verify_data.
     */
    public static function verifyFinished(string $finishedKey, string $transcriptHash, string $verifyData, bool $standard): bool
    {
        return hash_equals(self::computeFinished($finishedKey, $transcriptHash, $standard), $verifyData);
    }

    /**
     * Derive the 64-octet Ed25519 secret key (seed||public, RFC 8032) from its
     * 32-octet seed via ext-sodium.
     */
    public static function ed25519SecretKeyFromSeed(string $seed): string
    {
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        return sodium_crypto_sign_secretkey($keypair);
    }

    /**
     * The section 6.1 signing input: 64 octets of 0x20, the role context string,
     * a 0x00 separator, then the transcript hash - TLS-1.3-style domain
     * separation (RFC 8446 section 4.4.3).
     */
    public static function certVerifySigningInput(bool $isServer, string $transcriptHash): string
    {
        $ctx = $isServer ? self::CONTEXT_SERVER_CERTVERIFY : self::CONTEXT_CLIENT_CERTVERIFY;
        return str_repeat("\x20", 64) . $ctx . "\x00" . $transcriptHash;
    }

    /**
     * The CertVerify TLV value: u16(0x0807, Ed25519) | Ed25519(priv, signing_input).
     * $secretKey is the 64-octet libsodium secret key (seed||public).
     */
    public static function signCertVerify(string $secretKey, bool $isServer, string $transcriptHash): string
    {
        $sig = sodium_crypto_sign_detached(self::certVerifySigningInput($isServer, $transcriptHash), $secretKey);
        return Npamp::uintToBytes(Npamp::SIG_ED25519, 2) . $sig;
    }

    /**
     * Check a CertVerify TLV value against the signer's public key, role, and
     * transcript hash. Rejects a non-Ed25519 scheme, a wrong-length signature,
     * a role/context mismatch, or a wrong transcript.
     *
     * @param string $publicKey 32-octet Ed25519 public key
     */
    public static function verifyCertVerify(string $publicKey, bool $isServer, string $transcriptHash, string $value): bool
    {
        if (strlen($value) < 2 || Npamp::bytesToUint(substr($value, 0, 2)) !== Npamp::SIG_ED25519) {
            return false;
        }
        $sig = substr($value, 2);
        if (strlen($sig) !== 64) { // Ed25519 signatures are exactly 64 octets (RFC 8032 5.1.6)
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, self::certVerifySigningInput($isServer, $transcriptHash), $publicKey);
        } catch (\SodiumException $e) {
            return false;
        }
    }
}
