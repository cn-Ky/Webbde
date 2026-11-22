#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod scanner;
use tauri::Emitter;

#[tauri::command]
async fn scan(app: tauri::AppHandle, url: String, depth: usize) -> Result<scanner::Report, String> {
    let p = move |m: String| { let _ = app.emit("progress", m); };
    scanner::run(url, depth, &p).await
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![scan]).run(tauri::generate_context!()).expect("Webbde başlatılamadı");
}
