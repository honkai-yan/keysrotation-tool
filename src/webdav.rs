use crate::crypto::Res;
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::Method;
use std::time::Duration;
use url::Url;

pub const DB_NAME: &str = "ptoolkit_keys.db";

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
        _ => Err(format!("登录失败: {}", json["message"].as_str().unwrap_or("未知错误")).into()),
    }
}

/// 用已保存的 token 调用 /api/me 验证是否有效（无效或未登录时返回 guest）
pub fn token_valid(dav: &Url, token: &str) -> Res<bool> {
    let api = origin(dav)?.join("api/me")?;
    let resp = client()?.get(api.as_str()).header("Authorization", token).send()?;
    if resp.status().as_u16() != 200 {
        return Ok(false);
    }
    let json: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    Ok(json["code"] == 200 && json.pointer("/data/username").and_then(|u| u.as_str()) != Some("guest"))
}

fn db_url(dav: &Url) -> Res<Url> {
    let mut u = dav.clone();
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    Ok(u.join(DB_NAME)?)
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

/// 上传（覆盖）数据库
pub fn upload(dav: &Url, creds: Option<(&str, &str)>, data: Vec<u8>) -> Res<()> {
    let req = with_creds(client()?.put(db_url(dav)?.as_str()), creds);
    let resp = req.body(data).send()?;
    match resp.status().as_u16() {
        200..=299 => Ok(()),
        code => Err(format!("上传数据库失败: HTTP {code}").into()),
    }
}
