//! N-PAMP native Python extension: a thin PyO3/abi3 binding over the audited Rust core
//! (`npamp` crate). One implementation of the security-critical code, shipped as a
//! pre-built wheel so users never need a Rust toolchain (the pyca/cryptography model).
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn arr32(b: &[u8]) -> PyResult<[u8; 32]> {
    b.try_into().map_err(|_| PyValueError::new_err("key must be 32 bytes"))
}
fn arr12(b: &[u8]) -> PyResult<[u8; 12]> {
    b.try_into().map_err(|_| PyValueError::new_err("iv must be 12 bytes"))
}

#[pyfunction]
fn crc32c(data: &[u8]) -> u32 {
    npamp::crc32c(data)
}

#[pyfunction]
fn derive_nonce<'py>(py: Python<'py>, iv: &[u8], seq: u64) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &npamp::derive_nonce(&arr12(iv)?, seq)))
}

#[pyfunction]
fn seal_aes256gcm<'py>(py: Python<'py>, key: &[u8], iv: &[u8], seq: u64, aad: &[u8], pt: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &npamp::seal_aes256gcm(&arr32(key)?, &arr12(iv)?, seq, aad, pt)))
}

#[pyfunction]
fn open_aes256gcm<'py>(py: Python<'py>, key: &[u8], iv: &[u8], seq: u64, aad: &[u8], sealed: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    match npamp::open_aes256gcm(&arr32(key)?, &arr12(iv)?, seq, aad, sealed) {
        Ok(pt) => Ok(PyBytes::new(py, &pt)),
        Err(_) => Err(PyValueError::new_err("aead authentication failed")),
    }
}

#[pyfunction]
fn hkdf_expand_label<'py>(py: Python<'py>, secret: &[u8], label: &str, context: &[u8], length: usize, standard: bool) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &npamp::hkdf_expand_label(secret, label, context, length, standard))
}

#[pyfunction]
fn derive_traffic_secret<'py>(py: Python<'py>, master: &[u8], dir: u8, epoch: u64, suite: u16, channel: u16, standard: bool) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &npamp::derive_traffic_secret(master, dir, epoch, suite, channel, standard))
}

#[pyfunction]
fn derive_key_iv<'py>(py: Python<'py>, secret: &[u8], standard: bool) -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
    let (k, v) = npamp::derive_key_iv(secret, standard);
    (PyBytes::new(py, &k), PyBytes::new(py, &v))
}

#[pyfunction]
fn frame_marshal<'py>(py: Python<'py>, version: u8, flags: u8, ftype: u16, channel: u16, seq: u64, payload: &[u8]) -> Bound<'py, PyBytes> {
    let f = npamp::Frame { version, flags, ftype, channel, seq, payload: payload.to_vec() };
    PyBytes::new(py, &f.marshal())
}

/// Native module. Mirrors the pure-Python reference API so callers can swap backends.
#[pymodule]
fn npamp_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("AEAD_AES256_GCM", npamp::AEAD_AES256_GCM)?;
    m.add("CHAN_CONTROL", npamp::CHAN_CONTROL)?;
    m.add("FRAME_PING", npamp::FRAME_PING)?;
    m.add("LABEL_PREFIX", npamp::LABEL_PREFIX)?;
    m.add_function(wrap_pyfunction!(crc32c, m)?)?;
    m.add_function(wrap_pyfunction!(derive_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(seal_aes256gcm, m)?)?;
    m.add_function(wrap_pyfunction!(open_aes256gcm, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_expand_label, m)?)?;
    m.add_function(wrap_pyfunction!(derive_traffic_secret, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key_iv, m)?)?;
    m.add_function(wrap_pyfunction!(frame_marshal, m)?)?;
    Ok(())
}
