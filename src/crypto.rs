use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub type Key = [u8; 32];
pub type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn new_salt() -> [u8; 16] {
    rand::random()
}

/// 用 Argon2id 从口令和盐派生 32 字节密钥
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Res<Key> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| format!("密钥派生失败: {e}"))?;
    Ok(out)
}

/// AES-256-GCM 加密，输出 base64(nonce || ciphertext)
pub fn encrypt(key: &Key, plain: &str) -> Res<String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce: [u8; 12] = rand::random();
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plain.as_bytes())
        .map_err(|_| "加密失败")?;
    let mut buf = nonce.to_vec();
    buf.extend_from_slice(&ct);
    Ok(STANDARD.encode(buf))
}

pub fn decrypt(key: &Key, encoded: &str) -> Res<String> {
    let buf = STANDARD.decode(encoded)?;
    if buf.len() < 12 {
        return Err("密文长度非法".into());
    }
    let (nonce, ct) = buf.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher
        .decrypt(&Nonce::try_from(nonce).map_err(|_| "密文长度非法")?, ct)
        .map_err(|_| "解密失败，密钥可能不正确")?;
    Ok(String::from_utf8(pt)?)
}
