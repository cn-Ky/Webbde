# Webbde 0.2
Web sitesi güvenlik, mevzuat, yapay zekâ görünürlüğü ve kalite tarayıcısı. Rust + Tauri v2.

Yerelde: `cargo install tauri-cli --version "^2"` → `cargo tauri dev`.
Paket: `.github/workflows/build.yml` (GitHub Actions) üç işletim sistemi için derler.

## Kapsam (pasif)
Çok sayfalı nazik tarama (robots.txt'e uyar), TLS, başlıklar, çerezler, form ve DOM-XSS yüzeyi, eski JS kütüphaneleri,
izleyici envanteri, yasal sayfaların içerik kontrolü, SPF/DMARC (Cloudflare DoH), YZ bot erişimi ve "YZ gözüyle" görünüm.
Saldırı verisi göndermez; .env/.git gibi hassas yolları yoklamaz. Mevzuat kontrolleri işaret arar, hukuki görüş değildir.
