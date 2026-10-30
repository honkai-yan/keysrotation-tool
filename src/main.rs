// Release 构建下使用 Windows 子系统：不弹控制台窗口，只保留应用窗口。
// Debug 构建保留控制台，方便查看日志和 panic 信息。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod crypto;
mod db;
mod sync;
mod webdav;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("密钥轮换")
            .with_inner_size([880.0, 620.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "rust_keyrotation",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
