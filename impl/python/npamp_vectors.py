"""Emit the cross-language conformance vectors as JSON, byte-identical to Go."""
import npamp as n


def main():
    header = n.Frame(ftype=n.FRAME_PING, channel=n.CHAN_CONTROL, seq=0).marshal()
    iv = bytes(range(1, 13))
    nonce = n.derive_nonce(iv, 0x0102030405060708)
    key = bytes(range(32))
    iv2 = bytes(0x10 + i for i in range(12))
    aad = n.Frame(ftype=n.FRAME_PING, channel=n.CHAN_CONTROL).header_prefix(11)
    sealed = n.seal_aes256gcm(key, iv2, 7, aad, b"hello world")
    print(
        '{\n  "spec": "draft-bubblefish-npamp-00",\n'
        '  "header_ping_control_seq0": "%s",\n'
        '  "nonce_iv1to12_seq0102": "%s",\n'
        '  "aes256gcm_seal_helloworld": "%s"\n}'
        % (header.hex(), nonce.hex(), sealed.hex())
    )


if __name__ == "__main__":
    main()
