use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
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
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|_| "KDF 参数错误")?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| format!("密钥派生失败: {e}"))?;
    Ok(out)
}

/// AES-256-GCM 加密，输出 base64(nonce || ciphertext)
pub fn encrypt(key: &Key, plain: &str) -> Res<String> {
    if plain.len() > keyrotation_protocol::MAX_PLAINTEXT_BYTES {
        return Err("内容不能超过 32 KiB".into());
    }
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
    if !(28..=keyrotation_protocol::MAX_CIPHERTEXT_BYTES).contains(&buf.len()) {
        return Err("密文长度非法".into());
    }
    let (nonce, ct) = buf.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher
        .decrypt(&Nonce::try_from(nonce).map_err(|_| "密文长度非法")?, ct)
        .map_err(|_| "解密失败，密钥可能不正确")?;
    let pt = zeroize::Zeroizing::new(pt);
    Ok(std::str::from_utf8(&pt)?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_kdf_and_ciphertext_remain_compatible_and_authenticated() {
        let salt = [3u8; 16];
        let key = derive_key("synthetic-content-key", &salt).unwrap();
        let mut legacy_key = [0; 32];
        Argon2::default()
            .hash_password_into(b"synthetic-content-key", &salt, &mut legacy_key)
            .unwrap();
        assert_eq!(key, legacy_key);
        for plain in ["", "多语言内容 🔑", "ptoolkit-ok"] {
            let encrypted = encrypt(&legacy_key, plain).unwrap();
            assert_eq!(decrypt(&key, &encrypted).unwrap(), plain);
            assert!(decrypt(&[9; 32], &encrypted).is_err());
        }
        assert!(decrypt(&key, &STANDARD.encode([0; 12])).is_err());
        assert!(
            encrypt(
                &key,
                &"x".repeat(keyrotation_protocol::MAX_PLAINTEXT_BYTES + 1)
            )
            .is_err()
        );
    }
}
