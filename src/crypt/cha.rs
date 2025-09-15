use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng}, AeadCore, ChaCha20Poly1305, Key, Nonce
};
use base64::{engine, Engine};
use crate::utils::errors::Errors;

/// Generate a random 256-bit key
pub fn generate_key() -> Key {
    ChaCha20Poly1305::generate_key(&mut OsRng)
}

/// return NONCE,CIPHERTEXT
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Errors> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bit unique nonce

    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e|Errors::Encryption(e.to_string()))?;
    Ok((nonce.to_vec(), ciphertext))
}

pub fn decrypt(key: &Key, nonce: Vec<u8>, ciphertext: &Vec<u8>) -> Result<Vec<u8>, Errors> {
    let cipher = ChaCha20Poly1305::new(key);
    if nonce.len() != 12 {
        return Err(Errors::FailedDecKey(format!("NONCE:{}",nonce.len()).to_string()));
    }

    let nonce = Nonce::from_slice(&nonce);

    let plaintext = cipher.decrypt(&nonce, ciphertext.as_slice())
        .map_err(|e|Errors::FailedDecKey(e.to_string()))?;
    Ok(plaintext)
}

#[allow(unused)]
pub fn decrypt_str(
    key: &Key,
    nonce_b64: &Vec<u8>,
    ciphertext_b64_str: &str
) -> Result<String, Errors> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_b64);

    let e = engine::general_purpose::STANDARD_NO_PAD;
    let ciphertext = e.decode(ciphertext_b64_str)
        .map_err(|e| Errors::Decode64(e.to_string()))?;

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(raw_plain) => {
            let plain = String::from_utf8(raw_plain)
                .map_err(|e| Errors::PlainUTF8(e.to_string()))?;
            Ok(plain)
        },
        Err(e) => Err(Errors::FailedDecKey(e.to_string())),
    }
}

#[allow(unused)]
pub fn encrypt_str(
    key: &Key,
    plaintext: &str
) -> Result<(Vec<u8>,String), Errors> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bit unique nonce
    
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e|Errors::FailedDecKey(e.to_string()))?;

    let e = engine::general_purpose::STANDARD_NO_PAD;
    Ok((nonce.to_vec(), e.encode(ciphertext)))
}
