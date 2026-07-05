use npamp::*;

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// --- cross-language vector reproduction (values from the Go reference) ---

#[test]
fn vec_header() {
    let f = Frame { ftype: FRAME_PING, channel: CHAN_CONTROL, seq: 0, ..Default::default() };
    assert_eq!(hexs(&f.marshal()), "4e50414d20000100000000000000000000000000000d880c250000000000000000000000");
}

#[test]
fn vec_nonce() {
    let mut iv = [0u8; 12];
    for i in 0..12 { iv[i] = (i as u8) + 1; }
    assert_eq!(hexs(&derive_nonce(&iv, 0x0102_0304_0506_0708)), "010203040404040c0c0c0c04");
}

#[test]
fn vec_aead() {
    let mut key = [0u8; 32];
    for i in 0..32 { key[i] = i as u8; }
    let mut iv = [0u8; 12];
    for i in 0..12 { iv[i] = 0x10 + (i as u8); }
    let mut aad = [0u8; 21];
    Frame { ftype: FRAME_PING, channel: CHAN_CONTROL, ..Default::default() }.header_prefix(&mut aad, 11);
    assert_eq!(hexs(&seal_aes256gcm(&key, &iv, 7, &aad, b"hello world")), "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf");
}

#[test]
fn vec_traffic_key() {
    let master = vec![0x2Au8; 48];
    let ts = derive_traffic_secret(&master, 0, 0, AEAD_AES256_GCM, CHAN_CONTROL, false);
    let (tk, _) = derive_key_iv(&ts, false);
    assert_eq!(hexs(&tk), "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc");
}

// --- property tests (mirror the Go suite) ---

#[test]
fn roundtrip() {
    let f = Frame { flags: FLAG_ENC, ftype: 0x0100, channel: CHAN_MEMORY, seq: 42, payload: b"payload".to_vec(), ..Default::default() };
    let g = Frame::unmarshal(&f.marshal()).unwrap();
    assert_eq!(g.flags, FLAG_ENC);
    assert_eq!(g.ftype, 0x0100);
    assert_eq!(g.channel, CHAN_MEMORY);
    assert_eq!(g.seq, 42);
    assert_eq!(g.payload, b"payload");
}

#[test]
fn crc_validated_first() {
    let mut buf = Frame { ftype: FRAME_PING, ..Default::default() }.marshal();
    buf[5] ^= 0xFF;
    assert_eq!(Frame::unmarshal(&buf), Err(FrameError::BadCrc));
}

#[test]
fn reserved_must_be_zero() {
    let mut buf = Frame { ftype: FRAME_PING, ..Default::default() }.marshal();
    buf[30] = 1;
    assert_eq!(Frame::unmarshal(&buf), Err(FrameError::ReservedNonzero));
}

#[test]
fn aead_tamper_fails() {
    let key = [0u8; 32];
    let mut iv = [0u8; 12];
    for i in 0..12 { iv[i] = 0x10 + (i as u8); }
    let mut aad = [0u8; 21];
    Frame { ftype: FRAME_PING, ..Default::default() }.header_prefix(&mut aad, 5);
    let sealed = seal_aes256gcm(&key, &iv, 7, &aad, b"hello");
    assert_eq!(open_aes256gcm(&key, &iv, 7, &aad, &sealed).unwrap(), b"hello");
    aad[5] ^= 1;
    assert!(open_aes256gcm(&key, &iv, 7, &aad, &sealed).is_err());
}

#[test]
fn hkdf_prefix_protocol_specific() {
    assert_eq!(LABEL_PREFIX, "n-pamp ");
    assert_ne!(LABEL_PREFIX, "tls13 ");
}
