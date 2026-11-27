#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod scanner;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use tauri::{Emitter, State};

// Çalışan taramayı durdurmak için paylaşılan bayrak
#[derive(Default)]
struct Cancel(Arc<AtomicBool>);

#[tauri::command]
async fn scan(app: tauri::AppHandle, state: State<'_, Cancel>, url: String, depth: usize) -> Result<scanner::Report, String> {
    state.0.store(false, Ordering::Relaxed);
    let flag = state.0.clone();
    let p = move |m: String| { let _ = app.emit("progress", m); };
    scanner::run(url, depth, flag, &p).await
}

#[tauri::command]
fn cancel_scan(state: State<'_, Cancel>) { state.0.store(true, Ordering::Relaxed); }

fn main() {
    tauri::Builder::default()
        .manage(Cancel::default())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![scan, cancel_scan]).run(tauri::generate_context!()).expect("Webbde başlatılamadı");
}
