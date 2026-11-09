#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
extern crate gpui_kit as gpui;
mod api;
mod app;
mod config;
mod crypto;
mod sync;
mod ui;

fn main() {
    ui::run(app::App::new);
}
