use crate::crypto::Res;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    pub server_url: String,
    pub sym_key: String,
    pub username: Option<String>,
    pub token: Option<String>,
    pub trusted_servers: BTreeMap<String, String>,
    pub trusted_ca_files: BTreeMap<String, String>,
    pub legacy_endpoint: Option<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 2,
            server_url: String::new(),
            sym_key: String::new(),
            username: None,
            token: None,
            trusted_servers: BTreeMap::new(),
            trusted_ca_files: BTreeMap::new(),
            legacy_endpoint: None,
        }
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        self.sym_key.zeroize();
        if let Some(token) = &mut self.token {
            token.zeroize();
        }
    }
}

pub fn path() -> Option<PathBuf> {
    home::home_dir().map(|home| home.join(".rust-keyrotation/config.json"))
}

pub fn load_at(path: &Path) -> Res<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let bytes = zeroize::Zeroizing::new(fs::read(path)?);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if let Some(version) = value.get("config_version") {
        if version.as_u64() != Some(2) {
            return Err("不支持的配置版本".into());
        }
        return Ok(serde_json::from_value(value)?);
    }
    let mut config = Config::default();
    config.server_url = value
        .get("server_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    config.sym_key = value
        .get("sym_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    config.legacy_endpoint = Some(config.server_url.clone());
    Ok(config)
}

pub fn save_at(path: &Path, config: &Config) -> Res<()> {
    let directory = path.parent().ok_or("配置路径无父目录")?;
    if fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("配置目录不能是符号链接".into());
    }
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let temporary = directory.join(format!(".config-{}.tmp", keyrotation_protocol::random_id()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(config)?);
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(directory)?.sync_all()?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })();
    let _ = fs::remove_file(temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_credentials_are_not_forwarded_and_api_confirmation_is_required() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path,r#"{"server_url":"http://localhost/dav/","sym_key":"synthetic-content-key","username":"old-user","password":"old-password","token":"old-token"}"#).unwrap();
        let config = load_at(&path).unwrap();
        assert_eq!(config.sym_key, "synthetic-content-key");
        assert!(config.token.is_none());
        assert!(config.username.is_none());
        assert!(config.legacy_endpoint.is_some());
        save_at(&path, &config).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("old-password"));
        assert!(!text.contains("old-token"));
        assert_eq!(load_at(&path).unwrap().config_version, 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn malformed_or_newer_config_is_reported_instead_of_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, r#"{"config_version":99}"#).unwrap();
        assert!(load_at(&path).is_err());
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            r#"{"config_version":99}"#
        );
    }
}
