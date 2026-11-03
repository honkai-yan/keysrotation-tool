#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
extern crate gpui_kit as gpui;
mod app;
mod config;
mod crypto;
mod db;
mod sync;
mod ui;
mod webdav;

fn main() {
    ui::run(app::App::new);
}
