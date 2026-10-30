use crate::crypto::Res;
use reqwest::Method;
use reqwest::blocking::{Client, RequestBuilder};
use std::time::Duration;
use url::Url;

pub const DB_NAME: &str = "ptoolkit_keys.db";
pub const TMP_DB_NAME: &str = "ptoolkit_keys.db.tmp";

fn client() -> Res<Client> {
    Ok(Client::builder().timeout(Duration::from_secs(30)).build()?)
}

/// 服务器根地址（scheme://host:port/），用于调用 OpenList 的 /api 接口
pub fn origin(dav: &Url) -> Res<Url> {
    let mut o = dav.clone();
    o.set_path("/");
    o.set_query(None);
    o.set_fragment(None);
    Ok(o)
}

/// 添加 WebDAV Basic 认证（WebDAV 不接受 token）
fn with_creds(req: RequestBuilder, creds: Option<(&str, &str)>) -> RequestBuilder {
    match creds {
        Some((u, p)) => req.basic_auth(u, Some(p)),
        None => req,
    }
}

/// 无认证发送 PROPFIND：401 表示需要登录
pub fn auth_required(dav: &Url) -> Res<bool> {
    let resp = client()?
        .request(Method::from_bytes(b"PROPFIND")?, dav.as_str())
        .header("Depth", "0")
        .send()?;
    match resp.status().as_u16() {
        401 => Ok(true),
        200..=299 => Ok(false),
        code => Err(format!("服务器响应异常: HTTP {code}").into()),
    }
}

/// 登录 OpenList，返回 JWT token
pub fn login(dav: &Url, user: &str, pass: &str) -> Res<String> {
    let api = origin(dav)?.join("api/auth/login")?;
    let body = serde_json::json!({ "username": user, "password": pass }).to_string();
    let resp = client()?
        .post(api.as_str())
        .header("Content-Type", "application/json")
        .body(body)
        .send()?;
    let json: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    match json.pointer("/data/token").and_then(|t| t.as_str()) {
        Some(t) if json["code"] == 200 => Ok(t.to_string()),
        _ => Err(format!(
            "登录失败: {}",
            json["message"].as_str().unwrap_or("未知错误")
        )
        .into()),
    }
}

/// 用已保存的 token 调用 /api/me 验证是否有效（无效或未登录时返回 guest）
pub fn token_valid(dav: &Url, token: &str) -> Res<bool> {
    let api = origin(dav)?.join("api/me")?;
    let resp = client()?
        .get(api.as_str())
        .header("Authorization", token)
        .send()?;
    if resp.status().as_u16() != 200 {
        return Ok(false);
    }
    let json: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    Ok(json["code"] == 200
        && json.pointer("/data/username").and_then(|u| u.as_str()) != Some("guest"))
}

fn db_url(dav: &Url) -> Res<Url> {
    let mut u = dav.clone();
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    Ok(u.join(DB_NAME)?)
}

fn tmp_db_url(dav: &Url) -> Res<Url> {
    let mut u = dav.clone();
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    Ok(u.join(TMP_DB_NAME)?)
}

/// 下载数据库；404 返回 None，其他错误返回 Err
pub fn download(dav: &Url, creds: Option<(&str, &str)>) -> Res<Option<Vec<u8>>> {
    let req = with_creds(client()?.get(db_url(dav)?.as_str()), creds);
    let resp = req.send()?;
    match resp.status().as_u16() {
        200 => Ok(Some(resp.bytes()?.to_vec())),
        404 => Ok(None),
        code => Err(format!("下载数据库失败: HTTP {code}").into()),
    }
}

/// 删除临时文件，失败时忽略（用于失败后的尽力清理）
fn cleanup_tmp(client: &Client, dav: &Url, creds: Option<(&str, &str)>) {
    if let Ok(url) = tmp_db_url(dav) {
        let _ = with_creds(client.delete(url.as_str()), creds).send();
    }
}

/// 原子上传：先 PUT 到 .tmp，再用 WebDAV MOVE 覆盖主库。
/// OpenList 的 MOVE 支持 Overwrite: T，且目标存在时返回 201/204。
pub fn upload_atomic(dav: &Url, creds: Option<(&str, &str)>, data: Vec<u8>) -> Res<()> {
    let client = client()?;
    let tmp = tmp_db_url(dav)?;
    let dst = db_url(dav)?;

    let put = with_creds(client.put(tmp.as_str()), creds)
        .header("Content-Type", "application/x-sqlite3")
        .body(data)
        .send()?;
    if !put.status().is_success() {
        let code = put.status().as_u16();
        cleanup_tmp(&client, dav, creds);
        return Err(format!("上传数据库失败: HTTP {code}").into());
    }

    let moved = with_creds(
        client.request(Method::from_bytes(b"MOVE")?, tmp.as_str()),
        creds,
    )
    .header("Destination", dst.as_str())
    .header("Overwrite", "T")
    .send()?;
    if !moved.status().is_success() {
        let code = moved.status().as_u16();
        cleanup_tmp(&client, dav, creds);
        return Err(format!("上传数据库失败: HTTP {code}").into());
    }
    Ok(())
}
