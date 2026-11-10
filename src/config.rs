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
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("legacy_endpoint");
    }
    if value
        .get("config_version")
        .is_none_or(|version| version.as_u64() != Some(2))
    {
        return Err("不支持的配置版本，请重新填写 API 地址与内容口令".into());
    }
    Ok(serde_json::from_value(value)?)
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
        // Flushing the directory makes the rename durable on Unix. Windows has
        // no equivalent: opening a directory without FILE_FLAG_BACKUP_SEMANTICS
        // fails with ERROR_ACCESS_DENIED, which used to be reported after the
        // config file had already been replaced, so the save looked rejected.
        #[cfg(unix)]
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
    fn v2_round_trip_keeps_session_and_trust_but_never_a_login_password() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let mut config = Config::default();
        config.server_url = "http://127.0.0.1:8080/".into();
        config.sym_key = "synthetic-content-key".into();
        config.username = Some("admin".into());
        config.token = Some("synthetic-token".into());
        config
            .trusted_servers
            .insert(config.server_url.clone(), "c3ludGhldGljLXB1Yg==".into());
        save_at(&path, &config).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("password"));
        assert!(!text.contains("legacy_endpoint"));
        let loaded = load_at(&path).unwrap();
        assert_eq!(loaded.server_url, config.server_url);
        assert_eq!(loaded.sym_key, config.sym_key);
        assert_eq!(loaded.username.as_deref(), Some("admin"));
        assert_eq!(loaded.token.as_deref(), Some("synthetic-token"));
        assert_eq!(
            loaded
                .trusted_servers
                .get(&config.server_url)
                .map(String::as_str),
            Some("c3ludGhldGljLXB1Yg==")
        );
        assert_eq!(load_at(&path).unwrap().config_version, 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn retired_webdav_key_is_dropped_instead_of_blocking_a_v2_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            r#"{"config_version":2,"server_url":"http://127.0.0.1:8080/","sym_key":"synthetic-content-key","username":"admin","token":null,"trusted_servers":{"http://127.0.0.1:8080/":"c3ludGhldGljLXB1Yg=="},"trusted_ca_files":{},"legacy_endpoint":"http://localhost/dav/"}"#,
        )
        .unwrap();
        let config = load_at(&path).unwrap();
        assert_eq!(config.server_url, "http://127.0.0.1:8080/");
        save_at(&path, &config).unwrap();
        assert!(
            !fs::read_to_string(&path)
                .unwrap()
                .contains("legacy_endpoint")
        );
    }
    #[test]
    fn version_one_webdav_config_is_rejected_without_touching_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let original = r#"{"server_url":"http://localhost/dav/","sym_key":"synthetic-content-key","username":"old-user","password":"old-password","token":"old-token"}"#;
        fs::write(&path, original).unwrap();
        assert!(load_at(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
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
