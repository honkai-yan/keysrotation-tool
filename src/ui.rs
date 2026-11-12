use crate::app::{App as Model, Field, Overlay, Page};
use gpui_kit::base::Disableable;
use gpui_kit::{
    component::{
        button::*,
        input::{Input, InputEvent, InputState},
        menu::{ContextMenuExt, PopupMenuItem},
        spinner::Spinner,
    },
    prelude::*,
    *,
};
use std::time::{Duration, Instant};
use url::Url;

gpui_kit::actions!(keyrotation, [Quit]);

fn init_actions(cx: &mut App) {
    cx.on_action(|_: &Quit, cx| cx.quit());
    cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
    #[cfg(target_os = "macos")]
    cx.set_menus([Menu::new("密钥轮换").items([MenuItem::action("退出密钥轮换", Quit)])]);
}

const ACCENT: u32 = 0xd97757;
const INK: u32 = 0x302d2a;
const PAPER: u32 = 0xfaf9f5;

#[derive(Clone, Copy)]
enum FormField {
    Server,
    Port,
    Key,
    WizardServer,
    WizardKey,
    User,
    Password,
    WizardPublicKey,
    WizardCaFile,
}

pub struct Desktop {
    model: Model,
    inputs: Vec<Entity<InputState>>,
    _subscriptions: Vec<Subscription>,
    editor: Option<(i64, Field, Entity<InputState>, Subscription)>,
    _timer: Task<()>,
    #[cfg(test)]
    renders: usize,
}

impl Desktop {
    fn with_model(model: Model, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let fields = [
            FormField::Server,
            FormField::Port,
            FormField::Key,
            FormField::WizardServer,
            FormField::WizardKey,
            FormField::User,
            FormField::Password,
            FormField::WizardPublicKey,
            FormField::WizardCaFile,
        ];
        let mut inputs = Vec::new();
        let mut subscriptions = Vec::new();
        for field in fields {
            let value = Self::value(&model, field).to_owned();
            let input = cx.new(|cx| {
                InputState::new(window, cx)
                    .default_value(value)
                    .masked(matches!(
                        field,
                        FormField::Key | FormField::WizardKey | FormField::Password
                    ))
            });
            subscriptions.push(cx.subscribe_in(
                &input,
                window,
                move |this, input, event, _, cx| {
                    if this.blocked() {
                        return;
                    }
                    match event {
                        InputEvent::Change => {
                            let value = input.read(cx).value().to_string();
                            *Self::value_mut(&mut this.model, field) = value;
                            if matches!(field, FormField::WizardServer) {
                                let endpoint =
                                    keyrotation_transport::Endpoint::parse(&this.model.w_url).ok();
                                this.model.w_public_key = endpoint
                                    .as_ref()
                                    .and_then(|url| {
                                        this.model.cfg.trusted_servers.get(url.as_str())
                                    })
                                    .cloned()
                                    .unwrap_or_default();
                                this.model.w_ca_file = endpoint
                                    .as_ref()
                                    .and_then(|url| {
                                        this.model.cfg.trusted_ca_files.get(url.as_str())
                                    })
                                    .cloned()
                                    .unwrap_or_default();
                            } else if matches!(field, FormField::Server) {
                                this.model.port_buf = Url::parse(&this.model.url_buf)
                                    .ok()
                                    .and_then(|u| u.port_or_known_default())
                                    .map(|p| p.to_string())
                                    .unwrap_or_default();
                            } else if matches!(field, FormField::Port)
                                && let (Ok(port), Ok(mut url)) = (
                                    this.model.port_buf.parse::<u16>(),
                                    Url::parse(&this.model.url_buf),
                                )
                                && url.set_port(Some(port)).is_ok()
                            {
                                this.model.url_buf = url.to_string();
                            }
                        }
                        InputEvent::PressEnter { .. } => match field {
                            FormField::Server | FormField::Port => this.model.apply_url(),
                            FormField::Key => {
                                let key = std::mem::take(&mut this.model.key_buf);
                                if !key.is_empty() {
                                    this.model.change_key(key);
                                }
                            }
                            FormField::WizardServer
                            | FormField::WizardKey
                            | FormField::WizardPublicKey
                            | FormField::WizardCaFile
                            | FormField::User
                            | FormField::Password => this.model.wizard_confirm(),
                        },
                        InputEvent::Blur
                            if matches!(field, FormField::Server | FormField::Port) =>
                        {
                            this.model.apply_url()
                        }
                        _ => {}
                    }
                    cx.notify();
                },
            ));
            inputs.push(input);
        }
        let timer = cx.spawn_in(window, async |weak, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(50))
                    .await;
                if weak
                    .update_in(cx, |this, window, cx| {
                        let previous_overlay = this.model.overlay;
                        let previous_reveals = this.model.revealed.len();
                        let mut changed = false;
                        this.model.focused = window.is_window_active();
                        while let Some(event) = this.model.worker.try_recv() {
                            changed = true;
                            this.model.handle_event(event);
                        }
                        this.model.expire_reveals();
                        this.model.tick_sync();
                        // Drop input entities as soon as a reset removes their plaintext model state.
                        if this.model.edit.is_none() {
                            this.editor = None;
                        }
                        let flashing = [this.model.status_flash, this.model.auto_flash]
                            .into_iter()
                            .flatten()
                            .any(|start| start.elapsed() <= Duration::from_millis(450));
                        if changed
                            || previous_overlay != this.model.overlay
                            || previous_reveals != this.model.revealed.len()
                            || flashing
                        {
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            model,
            inputs,
            _subscriptions: subscriptions,
            editor: None,
            _timer: timer,
            #[cfg(test)]
            renders: 0,
        }
    }

    fn value(m: &Model, f: FormField) -> &str {
        match f {
            FormField::Server => &m.url_buf,
            FormField::Port => &m.port_buf,
            FormField::Key => &m.key_buf,
            FormField::WizardServer => &m.w_url,
            FormField::WizardKey => &m.w_key,
            FormField::User => &m.w_user,
            FormField::Password => &m.w_pass,
            FormField::WizardPublicKey => &m.w_public_key,
            FormField::WizardCaFile => &m.w_ca_file,
        }
    }
    fn value_mut(m: &mut Model, f: FormField) -> &mut String {
        match f {
            FormField::Server => &mut m.url_buf,
            FormField::Port => &mut m.port_buf,
            FormField::Key => &mut m.key_buf,
            FormField::WizardServer => &mut m.w_url,
            FormField::WizardKey => &mut m.w_key,
            FormField::User => &mut m.w_user,
            FormField::Password => &mut m.w_pass,
            FormField::WizardPublicKey => &mut m.w_public_key,
            FormField::WizardCaFile => &mut m.w_ca_file,
        }
    }
    fn blocked(&self) -> bool {
        self.model.overlay != Overlay::None || self.model.pending_delete.is_some()
    }

    fn reconcile(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for (index, field) in [
            FormField::Server,
            FormField::Port,
            FormField::Key,
            FormField::WizardServer,
            FormField::WizardKey,
            FormField::User,
            FormField::Password,
            FormField::WizardPublicKey,
            FormField::WizardCaFile,
        ]
        .into_iter()
        .enumerate()
        {
            let value = Self::value(&self.model, field);
            if self.inputs[index].read(cx).value().as_ref() != value {
                let value = value.to_owned();
                self.inputs[index].update(cx, |input, cx| input.set_value(value, window, cx));
            }
        }
        let Some(edit) = &self.model.edit else {
            self.editor = None;
            return;
        };
        if self
            .editor
            .as_ref()
            .is_some_and(|(id, field, _, _)| *id == edit.id && *field == edit.field)
        {
            return;
        }
        let (id, field, value) = (edit.id, edit.field, edit.buf.clone());
        let input = cx.new(|cx| InputState::new(window, cx).default_value(value));
        let subscription = cx.subscribe_in(&input, window, |this, input, event, _, cx| {
            if this.blocked() {
                return;
            }
            match event {
                InputEvent::Change => {
                    if let Some(edit) = &mut this.model.edit {
                        edit.buf = input.read(cx).value().to_string();
                    }
                }
                InputEvent::PressEnter { .. } => {
                    this.model.commit_edit();
                    this.editor = None;
                }
                _ => {}
            }
            cx.notify();
        });
        input.update(cx, |input, cx| input.focus(window, cx));
        self.editor = Some((id, field, input, subscription));
    }

    fn form_row(&self, label: &'static str, index: usize) -> impl IntoElement {
        div()
            .flex()
            .items_center()
            .gap_4()
            .child(div().w(px(120.)).child(label))
            .child(
                div()
                    .flex_1()
                    .child(Input::new(&self.inputs[index]).disabled(self.blocked())),
            )
    }

    fn cell(&self, id: i64, field: Field, text: String, cx: &mut Context<Self>) -> AnyElement {
        if field == Field::Content && self.model.reading.contains(&id) {
            return div()
                .flex_1()
                .px_3()
                .py_2()
                .flex()
                .gap_2()
                .child(Spinner::new())
                .child("加载中")
                .into_any_element();
        }
        if let Some((edit_id, edit_field, input, _)) = &self.editor
            && *edit_id == id
            && *edit_field == field
        {
            return div()
                .flex_1()
                .min_w_0()
                .child(Input::new(input).disabled(self.blocked()))
                .into_any_element();
        }
        let editing = self.model.edit.as_ref().is_some_and(|edit| edit.id == id);
        let revealed = self.model.revealed.contains_key(&id);
        let cell = div()
            .debug_selector(|| {
                if field == Field::Desc {
                    "description".into()
                } else {
                    "secret".into()
                }
            })
            .id((
                if field == Field::Desc {
                    "desc"
                } else {
                    "content"
                },
                id as u64,
            ))
            .flex_1()
            .min_w_0()
            .px_3()
            .py_2()
            .overflow_hidden()
            .cursor_pointer()
            .child(text)
            .on_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                if this.blocked() {
                    return;
                }
                if field == Field::Content && !this.model.revealed.contains_key(&id) {
                    this.model.reveal(id);
                } else if event.click_count() == 2 {
                    this.model.start_edit(id, field);
                }
                cx.notify();
            }));
        if field == Field::Desc && !editing {
            let weak = cx.entity().downgrade();
            cell.context_menu(move |menu, _, _| {
                let weak = weak.clone();
                menu.item(PopupMenuItem::new("删除").on_click(move |_, _, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        if !this.blocked() {
                            this.model.pending_delete = Some(id);
                            cx.notify();
                        }
                    });
                }))
            })
            .into_any_element()
        } else if field == Field::Content && revealed && !editing {
            cell.on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, _, _, cx| {
                    if this.blocked() {
                        return;
                    }
                    if let Some(value) = this.model.revealed.get(&id) {
                        cx.write_to_clipboard(ClipboardItem::new_string(value.plain.clone()));
                        this.model.set_status("复制成功");
                        cx.notify();
                    }
                }),
            )
            .into_any_element()
        } else {
            cell.into_any_element()
        }
    }

    fn main_page(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut rows = div().id("rows").flex_1().min_h_0().overflow_y_scroll();
        for row in &self.model.rows {
            let content = self
                .model
                .revealed
                .get(&row.id)
                .map(|r| r.plain.clone())
                .unwrap_or_else(|| "****************".into());
            rows = rows.child(
                div()
                    // GPUI retains hover state only for elements with a stable ID.
                    .id(("entry-row", row.id as u64))
                    .flex()
                    .w_full()
                    .border_b_1()
                    .border_color(rgb(0xeae6df))
                    .hover(|style| style.bg(rgb(0xf1e6de)))
                    .child(self.cell(row.id, Field::Desc, row.description.clone(), cx))
                    .child(self.cell(row.id, Field::Content, content, cx)),
            );
        }
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child("服务器地址")
                    .child(
                        div()
                            .flex_1()
                            .child(Input::new(&self.inputs[0]).disabled(self.blocked())),
                    )
                    .child("端口")
                    .child(
                        div()
                            .w(px(72.))
                            .child(Input::new(&self.inputs[1]).disabled(self.blocked())),
                    )
                    .child("对称加密密钥")
                    .child(
                        div()
                            .w(px(200.))
                            .child(Input::new(&self.inputs[2]).disabled(self.blocked())),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        Button::new("add")
                            .primary()
                            .label("新增")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if !this.blocked() {
                                    this.model.add_row();
                                    cx.notify();
                                }
                            })),
                    )
                    .child(format!("共 {} 条", self.model.rows.len()))
                    .child(div().flex_1())
                    .child(
                        Button::new("logout")
                            .label("退出登录")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if !this.blocked() {
                                    this.model.logout();
                                    cx.notify();
                                }
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .bg(rgb(0xeee9e1))
                    .py_2()
                    .child(div().flex_1().px_3().child("描述"))
                    .child(div().flex_1().px_3().child("内容")),
            )
            .child(rows)
            .into_any_element()
    }

    fn notice(text: String, start: Option<Instant>) -> impl IntoElement {
        let flash = start.is_some_and(|t| {
            t.elapsed() < Duration::from_millis(400)
                && (t.elapsed().as_millis() / 100).is_multiple_of(2)
        });
        div()
            .text_color(rgb(if flash { ACCENT } else { INK }))
            .child(text)
    }
}

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        #[cfg(test)]
        {
            self.renders += 1;
        }
        self.reconcile(window, cx);
        let body = match self.model.page {
            Page::Main => self.main_page(cx),
            Page::Wizard => div()
                .flex()
                .flex_col()
                .gap_4()
                .w(px(580.))
                .child(div().text_xl().child("服务器配置"))
                .child(self.form_row("服务器地址", 3))
                .child(self.form_row("对称加密密钥", 4))
                .child(if self.model.w_url.trim().starts_with("http://") {
                    self.form_row("可信服务端公钥", 7).into_any_element()
                } else {
                    self.form_row("可信 CA 文件（可选）", 8).into_any_element()
                })
                .child(self.form_row("账号", 5))
                .child(self.form_row("密码", 6))
                .when(self.model.cfg.token.is_some(), |this| {
                    this.child(
                        div()
                            .text_color(rgb(0x8a8074))
                            .child("密码留空则沿用已保存的登录会话"),
                    )
                })
                .child(
                    Button::new("confirm")
                        .primary()
                        .label("确认")
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.blocked() {
                                this.model.wizard_confirm();
                                cx.notify();
                            }
                        })),
                )
                .into_any_element(),
            Page::Initialize => div()
                .flex()
                .flex_col()
                .gap_4()
                .child("服务器数据库尚未初始化")
                .child("确认使用当前内容密钥创建空密钥库？")
                .child(
                    Button::new("initialize-vault")
                        .primary()
                        .label("初始化")
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.blocked() {
                                this.model.initialize_vault();
                                cx.notify();
                            }
                        })),
                )
                .into_any_element(),
            Page::Retry => div()
                .flex()
                .flex_col()
                .gap_4()
                .child("连接失败")
                .child(self.model.status.clone())
                .child(Button::new("retry").label("重试").on_click(cx.listener(
                    |this, _, _, cx| {
                        if !this.blocked() {
                            this.model.start_connect(true);
                            cx.notify();
                        }
                    },
                )))
                .child(
                    Button::new("configure")
                        .label("修改配置")
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.blocked() {
                                this.model.open_config();
                                cx.notify();
                            }
                        })),
                )
                .into_any_element(),
        };
        let mut root = div()
            .id("desktop")
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(PAPER))
            .text_color(rgb(INK))
            .text_sm()
            .font(Font {
                family: "Noto Sans SC".into(),
                fallbacks: Some(FontFallbacks::default()),
                ..Default::default()
            })
            .capture_key_down(cx.listener(|this, event: &KeyDownEvent, _, cx| {
                // Application shortcuts must reach the global action handler even
                // while a sync overlay or delete confirmation blocks editing.
                if event.keystroke == Keystroke::parse("cmd-q").expect("valid shortcut") {
                    return;
                }
                if this.blocked() {
                    cx.stop_propagation();
                    return;
                }
                if !this.blocked() && event.keystroke.key == "escape" {
                    this.model.cancel_edit();
                    this.editor = None;
                    cx.notify();
                }
            }))
            .child(div().p_4().flex_1().min_h_0().flex().flex_col().child(body))
            .child(
                div()
                    .flex()
                    .flex_shrink_0()
                    .items_center()
                    .justify_between()
                    .px_4()
                    .py_2()
                    .border_t_1()
                    .border_color(rgb(0xe3ded6))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(Self::notice(
                                self.model.status.clone(),
                                self.model.status_flash,
                            ))
                            .when_some(self.model.config_error.clone(), |this, error| {
                                this.child(
                                    div()
                                        .flex()
                                        .gap_2()
                                        .items_center()
                                        .text_color(rgb(0xc24e3a))
                                        .child(error)
                                        .child(
                                            Button::new("retry-save-config")
                                                .label("重试保存配置")
                                                .disabled(self.blocked())
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.model.retry_save_config();
                                                    cx.notify();
                                                })),
                                        ),
                                )
                            }),
                    )
                    .child(Self::notice(
                        self.model.auto_sync_notice.clone(),
                        self.model.auto_flash,
                    )),
            );
        if self.model.overlay != Overlay::None || self.model.pending_delete.is_some() {
            let mut overlay = div()
                .id("blocking-overlay")
                .absolute()
                .inset_0()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .bg(rgba(0x00000099))
                .occlude()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .on_key_down(|_, _, cx| cx.stop_propagation());
            if self.model.overlay == Overlay::Busy {
                overlay = overlay.child(
                    div()
                        .flex()
                        .flex_col()
                        .items_center()
                        .gap_4()
                        .child(Spinner::new().color(rgb(ACCENT).into()))
                        .when(self.model.can_cancel_rotation(), |this| {
                            this.child(Button::new("cancel-rotation").label("取消轮换").on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.model.cancel_rotation();
                                    cx.notify();
                                }),
                            ))
                        }),
                );
            } else if self.model.overlay == Overlay::Resolving {
                overlay = overlay.child(
                    div()
                        .flex()
                        .flex_col()
                        .items_center()
                        .gap_4()
                        .text_color(rgb(0xffffff))
                        .child(div().text_3xl().text_color(rgb(0xe04b4b)).child("×"))
                        .child(self.model.status.clone())
                        .when(self.model.can_cancel_rotation(), |this| {
                            this.child(
                                Button::new("cancel-unconfirmed-rotation")
                                    .label("取消轮换")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.model.cancel_rotation();
                                        cx.notify();
                                    })),
                            )
                        })
                        .child(
                            Button::new("resolve-retry")
                                .label(if self.model.pending_expired() {
                                    "重新加载"
                                } else {
                                    "重试"
                                })
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.model.retry_pending();
                                    cx.notify();
                                })),
                        )
                        .child(Button::new("resolve-logout").label("退出登录").on_click(
                            cx.listener(|this, _, _, cx| {
                                this.model.logout();
                                cx.notify();
                            }),
                        )),
                );
            } else if let Some(id) = self.model.pending_delete {
                overlay = overlay.child(
                    div()
                        .bg(rgb(PAPER))
                        .rounded_lg()
                        .p_6()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child("确定删除该密钥吗？")
                        .child(
                            div()
                                .flex()
                                .gap_3()
                                .child(Button::new("cancel-delete").label("取消").on_click(
                                    cx.listener(|this, _, _, cx| {
                                        this.model.pending_delete = None;
                                        cx.notify();
                                    }),
                                ))
                                .child(Button::new("delete").danger().label("删除").on_click(
                                    cx.listener(move |this, _, _, cx| {
                                        this.model.pending_delete = None;
                                        this.model.delete_row(id);
                                        cx.notify();
                                    }),
                                )),
                        ),
                );
            }
            root = root.child(overlay);
        }
        root
    }
}

use gpui_kit::component::Theme;

pub fn run(make_model: impl FnOnce() -> crate::app::App + 'static) {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx| {
            gpui_kit::init(cx);
            init_actions(cx);
            cx.text_system()
                .add_fonts(vec![std::borrow::Cow::Borrowed(include_bytes!(
                    "../assets/NotoSansSC-GB2312.otf"
                ))])
                .expect("内置字体加载失败");
            let theme = Theme::global_mut(cx);
            theme.font_family = "Noto Sans SC".into();
            theme.mono_font_family = "Noto Sans SC".into();
            theme.primary = rgb(0xd97757).into();
            theme.primary_hover = rgb(0xc56849).into();
            theme.background = rgb(0xfaf9f5).into();
            let bounds = Bounds::centered(None, size(px(1000.), px(620.)), cx);
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    titlebar: Some(TitlebarOptions {
                        title: Some("密钥轮换".into()),
                        ..Default::default()
                    }),
                    window_min_size: Some(size(px(800.), px(420.))),
                    ..Default::default()
                },
                cx,
                |window, cx| {
                    window.on_window_should_close(cx, |_, cx| {
                        cx.quit();
                        true
                    });
                    cx.new(|cx| Desktop::with_model(make_model(), window, cx))
                },
            )
            .expect("无法打开窗口");
            cx.activate(true);
        });
}

#[cfg(test)]
mod tests {
    use super::Desktop;
    use crate::app::{App as Model, Field};
    use gpui_kit::TestAppContext;

    #[gpui_kit::test]
    fn editor_enter_commits_and_escape_resumes_reveal(cx: &mut TestAppContext) {
        cx.update(gpui_kit::init);
        let (view, cx) =
            cx.add_window_view(|window, cx| Desktop::with_model(Model::test_vault(), window, cx));
        view.update(cx, |view, cx| {
            let id = view.model.rows[0].id;
            view.model.reveal(id);
            view.model.start_edit(id, Field::Content);
            cx.notify();
        });
        cx.run_until_parked();
        view.update(cx, |view, _| {
            assert!(view.editor.is_some());
            assert!(
                view.model
                    .revealed
                    .values()
                    .next()
                    .unwrap()
                    .paused_left
                    .is_some()
            );
        });
        cx.simulate_keystrokes("escape");
        view.update(cx, |view, _| {
            assert!(view.model.edit.is_none());
            assert!(view.editor.is_none());
            assert!(
                view.model
                    .revealed
                    .values()
                    .next()
                    .unwrap()
                    .paused_left
                    .is_none()
            );
        });
        cx.update(|window, cx| {
            view.update(cx, |view, cx| {
                let id = view.model.rows[0].id;
                view.model.start_edit(id, Field::Content);
                view.reconcile(window, cx);
            })
        });
        cx.simulate_keystrokes("cmd-a");
        cx.simulate_input("changed synthetic secret");
        cx.simulate_keystrokes("enter");
        view.update(cx, |view, _| {
            assert!(view.model.edit.is_none());
            assert_eq!(
                view.model.revealed.values().next().unwrap().plain,
                "changed synthetic secret"
            );
        });
    }

    #[gpui_kit::test]
    fn remote_replacement_drops_editor_and_plaintext(cx: &mut TestAppContext) {
        cx.update(gpui_kit::init);
        let (view, cx) =
            cx.add_window_view(|window, cx| Desktop::with_model(Model::test_vault(), window, cx));
        cx.update(|window, cx| {
            view.update(cx, |view, cx| {
                let id = view.model.rows[0].id;
                view.model.reveal(id);
                view.model.start_edit(id, Field::Content);
                view.reconcile(window, cx);
                assert!(view.editor.is_some());
                view.model = Model::test_vault();
                view.reconcile(window, cx);
                assert!(view.editor.is_none());
                assert!(view.model.revealed.is_empty());
            })
        });
    }
    #[gpui_kit::test]
    fn masked_content_cannot_copy_and_reveal_expires(cx: &mut TestAppContext) {
        use gpui_kit::{Modifiers, MouseButton};
        cx.update(gpui_kit::init);
        let (view, cx) =
            cx.add_window_view(|window, cx| Desktop::with_model(Model::test_vault(), window, cx));
        cx.run_until_parked();
        let point = cx
            .debug_bounds("secret")
            .expect("content cell rendered")
            .center();
        cx.simulate_mouse_down(point, MouseButton::Right, Modifiers::default());
        cx.simulate_mouse_up(point, MouseButton::Right, Modifiers::default());
        assert!(cx.read_from_clipboard().is_none());
        cx.simulate_click(point, Modifiers::default());
        cx.simulate_mouse_down(point, MouseButton::Right, Modifiers::default());
        cx.simulate_mouse_up(point, MouseButton::Right, Modifiers::default());
        assert_eq!(
            cx.read_from_clipboard().unwrap().text().as_deref(),
            Some("synthetic secret")
        );
        view.update(cx, |view, _| {
            assert_eq!(view.model.status, "复制成功");
            for revealed in view.model.revealed.values_mut() {
                revealed.expires = std::time::Instant::now() - std::time::Duration::from_secs(1);
            }
            view.model.expire_reveals();
            assert!(view.model.revealed.is_empty());
        });
    }

    #[gpui_kit::test]
    fn hover_repaints_on_pointer_transitions_without_waiting_for_sync(cx: &mut TestAppContext) {
        use gpui_kit::{Modifiers, point, px};
        cx.update(gpui_kit::init);
        let (view, cx) =
            cx.add_window_view(|window, cx| Desktop::with_model(Model::test_vault(), window, cx));
        cx.run_until_parked();
        let cell = cx.debug_bounds("secret").unwrap();
        let before = view.read_with(cx, |view, _| view.renders);
        cx.simulate_mouse_move(cell.center(), None, Modifiers::default());
        let entered = view.read_with(cx, |view, _| view.renders);
        assert!(
            entered > before,
            "pointer entry must repaint immediately, without advancing timers"
        );
        cx.simulate_mouse_move(point(cell.center().x, px(1.)), None, Modifiers::default());
        assert!(
            view.read_with(cx, |view, _| view.renders) > entered,
            "pointer exit must clear hover immediately"
        );
    }

    #[gpui_kit::test]
    fn cmd_q_reaches_app_handler_with_input_focus_and_blocking_overlays(cx: &mut TestAppContext) {
        use crate::app::Overlay;
        use std::{cell::Cell, rc::Rc};
        let calls = Rc::new(Cell::new(0));
        cx.update(|cx| {
            gpui_kit::init(cx);
            super::init_actions(cx);
            let calls = calls.clone();
            cx.on_action(move |_: &super::Quit, _| calls.set(calls.get() + 1));
        });
        let (view, cx) =
            cx.add_window_view(|window, cx| Desktop::with_model(Model::test_vault(), window, cx));
        for (index, overlay) in [Overlay::None, Overlay::Busy, Overlay::Resolving]
            .into_iter()
            .enumerate()
        {
            cx.update(|window, cx| {
                view.update(cx, |view, cx| {
                    view.model.overlay = overlay;
                    view.inputs[0].update(cx, |input, cx| input.focus(window, cx));
                    cx.notify();
                })
            });
            cx.simulate_keystrokes("cmd-q");
            assert_eq!(
                calls.get(),
                index + 1,
                "quit must work with focused inputs and sync overlays"
            );
        }
        view.update(cx, |view, cx| {
            view.model.overlay = Overlay::None;
            view.model.pending_delete = Some(view.model.rows[0].id);
            cx.notify();
        });
        cx.simulate_keystrokes("cmd-q");
        assert_eq!(calls.get(), 4, "delete confirmation must not trap quit");
    }
}
