use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// 持久化配置，保存在 ~/.rust-keyrotation/config.json（权限 600）
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Config {
    pub server_url: String,
    pub sym_key: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

pub fn dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".rust-keyrotation")
}

fn file() -> PathBuf {
    dir().join("config.json")
}

pub fn load() -> Option<Config> {
    let text = fs::read_to_string(file()).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save(cfg: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = dir();
    fs::create_dir_all(&dir)?;
    let path = file();
    let data = serde_json::to_vec_pretty(cfg)?;
    #[cfg(unix)]
    {
        use std::fs::{OpenOptions, Permissions, set_permissions};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        set_permissions(&dir, Permissions::from_mode(0o700))?;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        set_permissions(&path, Permissions::from_mode(0o600))?;
        f.write_all(&data)?;
    }
    #[cfg(not(unix))]
    fs::write(&path, data)?;
    Ok(())
}
