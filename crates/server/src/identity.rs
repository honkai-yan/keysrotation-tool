use keyrotation_protocol::{ApiError, ApiResult, ErrorCode};
use keyrotation_transport::Identity;
use std::{fs, io::Write, path::Path};

fn failure() -> ApiError {
    ApiError::new(ErrorCode::VaultUnavailable, "server identity unavailable")
}
pub fn load(directory: &Path) -> ApiResult<Identity> {
    let path = directory.join("identity.key");
    let metadata = fs::symlink_metadata(&path).map_err(|_| failure())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(failure());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(failure());
        }
    }
    let bytes = fs::read(path).map_err(|_| failure())?;
    let private: [u8; 32] = bytes.try_into().map_err(|_| failure())?;
    Ok(Identity::from_private(private))
}
pub fn create(directory: &Path) -> ApiResult<Identity> {
    let path = directory.join("identity.key");
    if path.exists() {
        return load(directory);
    }
    let identity = Identity::generate().map_err(|_| failure())?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| failure())?;
    file.write_all(identity.private_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| failure())?;
    Ok(identity)
}
