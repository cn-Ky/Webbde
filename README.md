# Webbde
Web sitesi güvenlik, mevzuat ve yapay zekâ görünürlüğü tarayıcısı. Rust + Tauri v2.

## Çalıştırma
1. Rust: https://rustup.rs  — Linux’ta ek olarak `libwebkit2gtk-4.1-dev build-essential libssl-dev`.
2. `cargo install tauri-cli --version "^2"`
3. `cargo tauri dev`        (geliştirme)
4. `cargo tauri icon src-tauri/icons/icon.png` ardından `cargo tauri build`  (.dmg / .msi / .deb / .AppImage)

## Kapsam
Pasif analiz: 1 sayfa isteği + robots.txt, llms.txt, sitemap.xml. Aktif XSS payload’ı göndermez.
Mevzuat kontrolleri işaret arar (KVKK, çerez, mesafeli satış); hukuki görüş değildir.
