mod app;
mod config;
mod crypto;
mod db;
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
