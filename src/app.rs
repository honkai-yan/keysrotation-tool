use crate::config::{self, Config};
use crate::crypto::{self, Key, Res};
use crate::db::{Db, Entry};
use crate::webdav;
use eframe::egui::{
    self, Align, Color32, Key as EKey, Label, Layout, RichText, Rect, Sense, Shape, Stroke,
    TextEdit, vec2,
};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

/// 明文密钥的自动恢复时间
const REVEAL_TTL: Duration = Duration::from_secs(60);
/// 用于校验对称密钥是否与数据库匹配的固定明文
const VERIFY_TEXT: &str = "ptoolkit-ok";
const MASK: &str = "****************";
const ROW_H: f32 = 22.0;

/// Claude 主题色
const CLAUDE: Color32 = Color32::from_rgb(0xD9, 0x77, 0x57);
const CLAUDE_HOVER: Color32 = Color32::from_rgba_premultiplied(0x30, 0x18, 0x10, 0x30);
const IVORY: Color32 = Color32::from_rgb(0xFA, 0xF9, 0xF5);

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Wizard,
    Login,
    Main,
    Retry,
}

#[derive(PartialEq, Clone, Copy)]
enum Field {
    Desc,
    Content,
}

struct Revealed {
    plain: String,
    expires: Instant,
    /// 编辑期间冻结倒计时时保存的剩余时间
    paused_left: Option<Duration>,
}

struct Edit {
    id: i64,
    field: Field,
    buf: String,
}

enum Connect {
    NeedLogin,
    Loaded(Option<Vec<u8>>),
}

enum Msg {
    Connected(Result<Connect, String>),
    /// (用户名, 密码, token, 数据库字节)
    LoggedIn(Result<(String, String, String, Option<Vec<u8>>), String>),
    Uploaded(Result<(), String>),
}

enum Act {
    Add,
    Reveal(i64),
    Edit(i64, Field),
    Commit,
    Cancel,
    Copy(String),
    Delete(i64),
}

pub struct App {
    page: Page,
    cfg: Config,
    ctx: egui::Context,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: bool,
    /// 状态栏文字
    status: String,
    /// "复制成功"闪烁开始时间
    flash: Option<Instant>,
    /// 当前是否为修改地址触发的重连
    reconnecting: bool,
    w_url: String,
    w_key: String,
    l_user: String,
    l_pass: String,
    url_buf: String,
    port_buf: String,
    key_buf: String,
    db: Option<Db>,
    cipher: Option<Key>,
    rows: Vec<Entry>,
    revealed: HashMap<i64, Revealed>,
    edit: Option<Edit>,
}

fn port_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.port_or_known_default())
        .map(|p| p.to_string())
        .unwrap_or_default()
}

fn valid_url(url: &str) -> bool {
    matches!(Url::parse(url), Ok(u) if matches!(u.scheme(), "http" | "https"))
}

/// 启动连接：先检测是否需要登录，需要则尝试 token 自动登录，否则下载数据库
fn connect_flow(dav: &Url, token: Option<&str>, creds: Option<&(String, String)>) -> Res<Connect> {
    if webdav::auth_required(dav)? {
        let token_ok = match token {
            Some(t) => webdav::token_valid(dav, t)?,
            None => false,
        };
        if !token_ok || creds.is_none() {
            return Ok(Connect::NeedLogin);
        }
    }
    let creds = creds.map(|(u, p)| (u.as_str(), p.as_str()));
    Ok(Connect::Loaded(webdav::download(dav, creds)?))
}

/// 打开（或新建）数据库并校验对称密钥
fn open_db(bytes: Option<Vec<u8>>, pass: &str) -> Res<(Db, Key, bool)> {
    match bytes {
        None => {
            let db = Db::new_empty()?;
            let salt = crypto::new_salt();
            let key = crypto::derive_key(pass, &salt)?;
            db.set_meta("salt", &salt)?;
            db.set_meta("verifier", crypto::encrypt(&key, VERIFY_TEXT)?.as_bytes())?;
            Ok((db, key, true))
        }
        Some(b) => {
            let db = Db::from_bytes(&b)?;
            let salt = db.meta("salt")?.ok_or("数据库缺少盐值")?;
            let key = crypto::derive_key(pass, &salt)?;
            let verifier = db.meta("verifier")?.ok_or("数据库缺少校验信息")?;
            if crypto::decrypt(&key, std::str::from_utf8(&verifier)?)? != VERIFY_TEXT {
                return Err("加密密钥与服务器数据库不匹配".into());
            }
            Ok((db, key, false))
        }
    }
}

fn setup_fonts(ctx: &egui::Context) {
    // 默认字体没有中文字形，从系统字体加载一个中文字体
    let candidates = [
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
    ];
    let mut fonts = egui::FontDefinitions::default();
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "cjk".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(bytes)),
            );
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts.families.entry(family).or_default().push("cjk".to_owned());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

fn setup_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::light();
    v.panel_fill = IVORY;
    v.window_fill = IVORY;
    v.selection.bg_fill = CLAUDE;
    v.hyperlink_color = CLAUDE;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, CLAUDE);
    v.widgets.active.bg_stroke = Stroke::new(1.0, CLAUDE);
    ctx.set_visuals(v);
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        setup_theme(&cc.egui_ctx);
        let (tx, rx) = channel();
        let cfg = config::load().unwrap_or_default();
        let mut app = App {
            page: Page::Wizard,
            ctx: cc.egui_ctx.clone(),
            tx,
            rx,
            busy: false,
            status: String::new(),
            flash: None,
            reconnecting: false,
            w_url: cfg.server_url.clone(),
            w_key: String::new(),
            l_user: cfg.username.clone().unwrap_or_default(),
            l_pass: String::new(),
            url_buf: cfg.server_url.clone(),
            port_buf: port_of(&cfg.server_url),
            key_buf: String::new(),
            db: None,
            cipher: None,
            rows: Vec::new(),
            revealed: HashMap::new(),
            edit: None,
            cfg,
        };
        if !app.cfg.server_url.is_empty() && !app.cfg.sym_key.is_empty() {
            app.connect(false);
        }
        app
    }

    fn dav_url(&self) -> Option<Url> {
        Url::parse(&self.cfg.server_url).ok()
    }

    fn creds(&self) -> Option<(String, String)> {
        match (&self.cfg.username, &self.cfg.password) {
            (Some(u), Some(p)) => Some((u.clone(), p.clone())),
            _ => None,
        }
    }

    fn save_cfg(&mut self) {
        if let Err(e) = config::save(&self.cfg) {
            self.status = format!("保存配置失败: {e}");
        }
    }

    /// 在后台线程执行网络任务，结果通过 channel 回到 UI 线程
    fn spawn_task<F>(&mut self, f: F)
    where
        F: FnOnce() -> Msg + Send + 'static,
    {
        self.busy = true;
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    fn connect(&mut self, reconnecting: bool) {
        let Some(dav) = self.dav_url() else {
            self.status = "服务器地址不合法".into();
            self.page = Page::Wizard;
            return;
        };
        self.reconnecting = reconnecting;
        let creds = self.creds();
        let token = self.cfg.token.clone();
        self.spawn_task(move || {
            Msg::Connected(
                connect_flow(&dav, token.as_deref(), creds.as_ref()).map_err(|e| e.to_string()),
            )
        });
    }

    fn login(&mut self) {
        let Some(dav) = self.dav_url() else { return };
        let user = self.l_user.trim().to_string();
        let pass = self.l_pass.clone();
        self.spawn_task(move || {
            let res = (|| -> Res<(String, Option<Vec<u8>>)> {
                let token = webdav::login(&dav, &user, &pass)?;
                let bytes = webdav::download(&dav, Some((&user, &pass)))?;
                Ok((token, bytes))
            })();
            Msg::LoggedIn(
                res.map(|(token, bytes)| (user, pass, token, bytes))
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn upload(&mut self) {
        let Some(db) = &mut self.db else { return };
        let bytes = match db.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                self.status = format!("导出数据库失败: {e}");
                return;
            }
        };
        let Some(dav) = self.dav_url() else { return };
        let creds = self.creds();
        self.spawn_task(move || {
            Msg::Uploaded(
                webdav::upload(&dav, creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())), bytes)
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn handle(&mut self, msg: Msg) {
        self.busy = false;
        match msg {
            Msg::Connected(Ok(Connect::NeedLogin)) => {
                if self.reconnecting {
                    self.unload();
                }
                self.reconnecting = false;
                self.l_user = self.cfg.username.clone().unwrap_or_default();
                self.l_pass.clear();
                self.page = Page::Login;
            }
            Msg::Connected(Ok(Connect::Loaded(bytes))) => self.on_db_bytes(bytes),
            Msg::Connected(Err(e)) => self.fail(e),
            Msg::LoggedIn(Ok((user, pass, token, bytes))) => {
                self.cfg.username = Some(user);
                self.cfg.password = Some(pass);
                self.cfg.token = Some(token);
                self.save_cfg();
                self.l_pass.clear();
                self.on_db_bytes(bytes);
            }
            Msg::LoggedIn(Err(e)) => self.status = e,
            Msg::Uploaded(Ok(())) => self.status = "同步完成".into(),
            Msg::Uploaded(Err(e)) => self.status = e,
        }
    }

    fn on_db_bytes(&mut self, bytes: Option<Vec<u8>>) {
        match open_db(bytes, &self.cfg.sym_key) {
            Ok((db, key, created)) => {
                self.db = Some(db);
                self.cipher = Some(key);
                self.page = Page::Main;
                self.reconnecting = false;
                self.status.clear();
                self.revealed.clear();
                self.edit = None;
                self.key_buf.clear();
                self.reload_rows();
                if created {
                    self.upload();
                }
            }
            Err(e) => self.fail(e.to_string()),
        }
    }

    /// 连接失败：重连时卸载数据库并回到向导，否则显示重试页
    fn fail(&mut self, msg: String) {
        self.status = msg;
        if self.reconnecting {
            self.reconnecting = false;
            self.unload();
            self.w_url = self.cfg.server_url.clone();
            self.page = Page::Wizard;
        } else {
            self.page = Page::Retry;
        }
    }

    fn unload(&mut self) {
        self.db = None;
        self.cipher = None;
        self.rows.clear();
        self.revealed.clear();
        self.edit = None;
    }

    fn reload_rows(&mut self) {
        if let Some(db) = &self.db {
            match db.entries() {
                Ok(rows) => self.rows = rows,
                Err(e) => self.status = format!("读取条目失败: {e}"),
            }
        }
    }

    fn wizard_confirm(&mut self) {
        let url = self.w_url.trim().to_string();
        if !valid_url(&url) {
            self.status = "服务器地址不合法".into();
            return;
        }
        if self.w_key.is_empty() {
            self.status = "加密密钥不能为空".into();
            return;
        }
        self.cfg.server_url = url.clone();
        self.cfg.sym_key = std::mem::take(&mut self.w_key);
        self.save_cfg();
        self.url_buf = url.clone();
        self.port_buf = port_of(&url);
        self.connect(false);
    }

    /// 地址框失焦或回车：地址变化则立刻重连
    fn apply_url(&mut self) {
        let url = self.url_buf.trim().to_string();
        if url == self.cfg.server_url {
            return;
        }
        if !valid_url(&url) {
            self.status = "服务器地址不合法".into();
            return;
        }
        self.cfg.server_url = url;
        self.save_cfg();
        self.connect(true);
    }

    fn change_key(&mut self, new_pass: String) {
        if new_pass == self.cfg.sym_key {
            return;
        }
        let (Some(db), Some(old_key)) = (&self.db, self.cipher) else { return };
        // 先用旧密钥解密全部条目，全部成功后再写入，避免中途失败留下半改状态
        let plains: Res<Vec<(i64, String)>> = db
            .entries()
            .and_then(|rows| {
                rows.iter()
                    .map(|e| Ok((e.id, crypto::decrypt(&old_key, &e.content)?)))
                    .collect()
            });
        let plains = match plains {
            Ok(p) => p,
            Err(e) => {
                self.status = format!("旧数据解密失败，未修改密钥: {e}");
                return;
            }
        };
        let salt = crypto::new_salt();
        let new_key = match crypto::derive_key(&new_pass, &salt) {
            Ok(k) => k,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        let encrypted: Res<Vec<(i64, String)>> = plains
            .iter()
            .map(|(id, p)| Ok((*id, crypto::encrypt(&new_key, p)?)))
            .collect();
        let encrypted = match encrypted {
            Ok(e) => e,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        let write = (|| -> Res<()> {
            db.set_meta("salt", &salt)?;
            db.set_meta("verifier", crypto::encrypt(&new_key, VERIFY_TEXT)?.as_bytes())?;
            for (id, content) in &encrypted {
                db.update_content(*id, content)?;
            }
            Ok(())
        })();
        if let Err(e) = write {
            self.status = format!("写入数据库失败: {e}");
            return;
        }
        self.cipher = Some(new_key);
        self.cfg.sym_key = new_pass;
        self.save_cfg();
        self.revealed.clear();
        self.edit = None;
        self.key_buf.clear();
        self.reload_rows();
        self.upload();
    }

    fn expire_reveals(&mut self) {
        let now = Instant::now();
        self.revealed
            .retain(|_, r| r.paused_left.is_some() || r.expires > now);
    }

    fn reveal(&mut self, id: i64) {
        let (Some(key), Some(row)) = (self.cipher, self.rows.iter().find(|r| r.id == id)) else {
            return;
        };
        match crypto::decrypt(&key, &row.content) {
            Ok(plain) => {
                self.revealed.insert(
                    id,
                    Revealed {
                        plain,
                        expires: Instant::now() + REVEAL_TTL,
                        paused_left: None,
                    },
                );
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    fn start_edit(&mut self, id: i64, field: Field) {
        self.cancel_edit();
        let buf = match field {
            Field::Desc => match self.rows.iter().find(|r| r.id == id) {
                Some(r) => r.desc.clone(),
                None => return,
            },
            Field::Content => match self.revealed.get_mut(&id) {
                Some(r) => {
                    // 编辑期间冻结倒计时
                    r.paused_left = Some(r.expires.saturating_duration_since(Instant::now()));
                    r.plain.clone()
                }
                None => return,
            },
        };
        self.edit = Some(Edit { id, field, buf });
    }

    fn cancel_edit(&mut self) {
        if let Some(ed) = self.edit.take() {
            if ed.field == Field::Content {
                if let Some(r) = self.revealed.get_mut(&ed.id) {
                    if let Some(left) = r.paused_left.take() {
                        r.expires = Instant::now() + left;
                    }
                }
            }
        }
    }

    fn commit_edit(&mut self) {
        let Some(ed) = self.edit.take() else { return };
        let Some(db) = &self.db else { return };
        match ed.field {
            Field::Desc => {
                if let Err(e) = db.update_desc(ed.id, &ed.buf) {
                    self.status = format!("保存失败: {e}");
                    return;
                }
            }
            Field::Content => {
                let Some(key) = self.cipher else { return };
                let enc = match crypto::encrypt(&key, &ed.buf) {
                    Ok(e) => e,
                    Err(e) => {
                        self.status = e.to_string();
                        return;
                    }
                };
                if let Err(e) = db.update_content(ed.id, &enc) {
                    self.status = format!("保存失败: {e}");
                    return;
                }
                // 修改后恢复明文显示，并重新开始 1 分钟倒计时
                self.revealed.insert(
                    ed.id,
                    Revealed {
                        plain: ed.buf,
                        expires: Instant::now() + REVEAL_TTL,
                        paused_left: None,
                    },
                );
            }
        }
        self.reload_rows();
        self.upload();
    }

    fn add_row(&mut self) {
        let Some(key) = self.cipher else { return };
        let Some(db) = &self.db else { return };
        let id = match crypto::encrypt(&key, "").and_then(|enc| db.insert("", &enc)) {
            Ok(id) => id,
            Err(e) => {
                self.status = format!("新增失败: {e}");
                return;
            }
        };
        self.reload_rows();
        // 新增后直接进入描述编辑
        self.start_edit(id, Field::Desc);
        self.upload();
    }

    fn delete_row(&mut self, id: i64) {
        let Some(db) = &self.db else { return };
        if let Err(e) = db.delete(id) {
            self.status = format!("删除失败: {e}");
            return;
        }
        self.revealed.remove(&id);
        if self.edit.as_ref().is_some_and(|ed| ed.id == id) {
            self.edit = None;
        }
        self.reload_rows();
        self.upload();
    }

    fn apply(&mut self, act: Act) {
        match act {
            Act::Add => self.add_row(),
            Act::Reveal(id) => self.reveal(id),
            Act::Edit(id, field) => self.start_edit(id, field),
            Act::Commit => self.commit_edit(),
            Act::Cancel => self.cancel_edit(),
            Act::Copy(text) => {
                self.ctx.copy_text(text);
                self.flash = Some(Instant::now());
            }
            Act::Delete(id) => self.delete_row(id),
        }
    }

    fn wizard_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("配置向导");
        ui.add_space(12.0);
        egui::Grid::new("wizard_form")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("服务器地址");
                ui.add(
                    TextEdit::singleline(&mut self.w_url)
                        .desired_width(420.0)
                        .hint_text("http://host:port/dav/"),
                );
                ui.end_row();
                ui.label("对称加密密钥");
                ui.add(TextEdit::singleline(&mut self.w_key).password(true).desired_width(420.0));
                ui.end_row();
            });
        ui.add_space(12.0);
        if ui.button("确认").clicked() {
            self.wizard_confirm();
        }
    }

    fn login_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("登录");
        ui.add_space(12.0);
        egui::Grid::new("login_form")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("账号");
                ui.add(TextEdit::singleline(&mut self.l_user).desired_width(320.0));
                ui.end_row();
                ui.label("密码");
                let pass = ui.add(TextEdit::singleline(&mut self.l_pass).password(true).desired_width(320.0));
                ui.end_row();
                if pass.lost_focus() && ui.input(|i| i.key_pressed(EKey::Enter)) {
                    self.login();
                }
            });
        ui.add_space(12.0);
        if ui.button("登录").clicked() {
            self.login();
        }
    }

    fn retry_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("连接失败");
        ui.add_space(12.0);
        ui.label(&self.status);
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("重试").clicked() {
                self.connect(false);
            }
            if ui.button("修改配置").clicked() {
                self.w_url = self.cfg.server_url.clone();
                self.w_key.clear();
                self.page = Page::Wizard;
            }
        });
    }

    fn main_ui(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("服务器地址");
                let url = ui.add(TextEdit::singleline(&mut self.url_buf).desired_width(300.0));
                if url.changed() {
                    self.port_buf = port_of(&self.url_buf);
                }
                ui.label("端口");
                let port = ui.add(TextEdit::singleline(&mut self.port_buf).desired_width(60.0));
                if port.changed() {
                    if let (Ok(p), Ok(mut u)) = (self.port_buf.parse::<u16>(), Url::parse(&self.url_buf)) {
                        if u.set_port(Some(p)).is_ok() {
                            self.url_buf = u.to_string();
                        }
                    }
                }
                if url.lost_focus() || port.lost_focus() {
                    self.apply_url();
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let key = ui.add(
                        TextEdit::singleline(&mut self.key_buf)
                            .password(true)
                            .hint_text("输入新密钥后回车")
                            .desired_width(200.0),
                    );
                    ui.label("对称加密密钥");
                    if key.lost_focus()
                        && ui.input(|i| i.key_pressed(EKey::Enter))
                        && !self.key_buf.is_empty()
                    {
                        let pass = std::mem::take(&mut self.key_buf);
                        self.change_key(pass);
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("新增").clicked() {
                    self.apply(Act::Add);
                }
                ui.label(format!("共 {} 条", self.rows.len()));
            });
            ui.separator();

            let total = ui.available_width();
            let w_desc = (total * 0.4).floor();
            let w_content = total - w_desc - ui.spacing().item_spacing.x;
            ui.horizontal(|ui| {
                ui.add_sized([w_desc, ROW_H], Label::new(RichText::new("描述").strong()));
                ui.add_sized([w_content, ROW_H], Label::new(RichText::new("内容").strong()));
            });
            ui.separator();

            let rows = self.rows.clone();
            let mut acts = Vec::new();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for e in &rows {
                        acts.extend(self.row_ui(ui, e, w_desc, w_content));
                    }
                });
            for act in acts {
                self.apply(act);
            }
        });
    }

    fn row_ui(&mut self, ui: &mut egui::Ui, e: &Entry, w_desc: f32, w_content: f32) -> Vec<Act> {
        let mut acts = Vec::new();
        let bg = ui.painter().add(Shape::Noop);
        let row = ui.horizontal(|ui| {
            // 描述：双击编辑，右键删除
            if self.edit.as_ref().is_some_and(|ed| ed.id == e.id && ed.field == Field::Desc) {
                let ed = self.edit.as_mut().unwrap();
                let r = ui.add_sized([w_desc, ROW_H], TextEdit::singleline(&mut ed.buf));
                edit_keys(&r, &mut acts);
            } else {
                let r = ui.add_sized([w_desc, ROW_H], Label::new(e.desc.as_str()).sense(Sense::click()));
                if r.double_clicked() {
                    acts.push(Act::Edit(e.id, Field::Desc));
                }
                r.context_menu(|ui| {
                    if ui.button("删除").clicked() {
                        acts.push(Act::Delete(e.id));
                        ui.close();
                    }
                });
            }

            // 内容：未解密显示 *，点击解密；解密后双击编辑，右键复制
            if self.edit.as_ref().is_some_and(|ed| ed.id == e.id && ed.field == Field::Content) {
                let ed = self.edit.as_mut().unwrap();
                let r = ui.add_sized([w_content, ROW_H], TextEdit::singleline(&mut ed.buf));
                edit_keys(&r, &mut acts);
            } else if let Some(rv) = self.revealed.get(&e.id) {
                let r = ui.add_sized([w_content, ROW_H], Label::new(rv.plain.as_str()).sense(Sense::click()));
                if r.double_clicked() {
                    acts.push(Act::Edit(e.id, Field::Content));
                }
                if r.secondary_clicked() {
                    acts.push(Act::Copy(rv.plain.clone()));
                }
            } else {
                let r = ui.add_sized([w_content, ROW_H], Label::new(MASK).sense(Sense::click()));
                if r.clicked() {
                    acts.push(Act::Reveal(e.id));
                }
            }
        });

        // 鼠标悬停时整行高亮
        let rect = row.response.rect;
        if ui.rect_contains_pointer(rect) {
            ui.painter().set(bg, Shape::rect_filled(rect, 4.0, CLAUDE_HOVER));
        }
        acts
    }

    fn overlay(&self, ui: &mut egui::Ui) {
        let screen: Rect = ui.ctx().content_rect();
        egui::Area::new(ui.scope_id().with("busy_overlay"))
            .order(egui::Order::Foreground)
            .fixed_pos(screen.min)
            .show(ui.ctx(), |ui| {
                ui.set_clip_rect(screen);
                ui.allocate_rect(screen, Sense::click_and_drag());
                ui.painter().rect_filled(screen, 0.0, Color32::from_black_alpha(110));
                let spinner_rect = Rect::from_center_size(screen.center(), vec2(48.0, 48.0));
                ui.put(spinner_rect, egui::Spinner::new().size(40.0).color(CLAUDE));
            });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status_bar").show(ui, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                let flash_ms = self.flash.map(|t| t.elapsed().as_millis());
                match flash_ms {
                    // "复制成功" 快速闪烁两次：只切换字体颜色，文字始终占位，避免布局跳动
                    Some(ms) if ms < 400 => {
                        let color = if (ms / 100) % 2 == 0 {
                            CLAUDE
                        } else {
                            ui.visuals().text_color()
                        };
                        ui.colored_label(color, "复制成功");
                    }
                    _ => {
                        ui.label(&self.status);
                    }
                }
            });
            ui.add_space(3.0);
        });
    }
}

/// 单行编辑框的键盘处理：回车提交，Esc 取消
fn edit_keys(r: &egui::Response, acts: &mut Vec<Act>) {
    if !r.has_focus() {
        r.request_focus();
    }
    let (enter, esc) = r.ctx.input(|i| (i.key_pressed(EKey::Enter), i.key_pressed(EKey::Escape)));
    if enter {
        acts.push(Act::Commit);
    } else if esc {
        acts.push(Act::Cancel);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        while let Ok(msg) = self.rx.try_recv() {
            self.handle(msg);
        }
        self.expire_reveals();

        self.status_bar(ui);
        let page = self.page;
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_enabled_ui(!self.busy, |ui| match page {
                Page::Wizard => self.wizard_ui(ui),
                Page::Login => self.login_ui(ui),
                Page::Main => self.main_ui(ui),
                Page::Retry => self.retry_ui(ui),
            });
        });

        if self.busy {
            self.overlay(ui);
        }

        if !self.revealed.is_empty() {
            self.ctx.request_repaint_after(Duration::from_millis(500));
        }
        if self.flash.is_some_and(|t| t.elapsed() < Duration::from_millis(400)) {
            self.ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}
