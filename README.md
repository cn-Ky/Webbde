# Webbde 0.3
Rust + Tauri v2 web sitesi tarayıcısı (güvenlik, mevzuat, YZ görünürlüğü, kalite). Otomatik güncellemeli.

## Sürüm yayınlama
1. `src-tauri/tauri.conf.json` içindeki `version` değerini artırın (ör. 0.3.1), commit edin.
2. GitHub → Actions → "Webbde sürüm yayınla" → Run workflow.
3. Bitince Releases bölümünde kurulum dosyaları ve `latest.json` oluşur. Yüklü uygulamalar açılışta güncellemeyi sunar.

## Bir kerelik kurulum (repo ayarları → Secrets and variables → Actions)
`npx @tauri-apps/cli signer generate -w ~/.tauri/webbde.key` ile anahtar üretin; şu üç secret'ı ekleyin:
- `TAURI_SIGNING_PRIVATE_KEY`: webbde.key dosyasının içeriği
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: anahtar parolası
- `UPDATER_PUBKEY`: webbde.key.pub dosyasının içeriği
Depo herkese açık (public) olmalı. Özel anahtarı kaybetmeyin.
