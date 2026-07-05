# npamp-native

Native Python extension for the **N-PAMP** wire format (draft-bubblefish-npamp-00):
A thin [PyO3](https://pyo3.rs) binding over the audited Rust core (`impl/rust`),
shipped as a pre-built **abi3** wheel so users never need a Rust toolchain. This is the
distribution model used by [pyca/cryptography](https://github.com/pyca/cryptography).

```python
import npamp_native as n
sealed = n.seal_aes256gcm(key, iv, 0, aad, b"hello world")  # ciphertext || tag
```

The pure-Python reference (`impl/python`) exposes the same API as a no-native-deps
fallback and as the cross-implementation conformance oracle. Build: `maturin build --release`.
