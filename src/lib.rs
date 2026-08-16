mod base64;
mod ecdh;
mod ed25519;
mod hex;
mod symmetric;

#[cfg(test)]
mod cross_platform_vectors;

pub use base64::{base64_decode, base64_encode};
pub use ecdh::EcdhSession;
pub use ed25519::{ed25519_generate, ed25519_sign, ed25519_verify};
pub use hex::bytes_to_hex;
pub use symmetric::{
    chacha20_decrypt, chacha20_encrypt, xchacha_decrypt, xchacha_decrypt_raw, xchacha_encrypt,
    xchacha_encrypt_raw,
};

pub fn gen_random(_buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(_buf);
        }
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    gen_random(&mut buf);
    buf
}

pub fn gen_token() -> String {
    let mut bytes = [0u8; 32];
    gen_random(&mut bytes);
    base64_encode(&bytes)
}
