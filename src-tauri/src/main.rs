#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use reqwest::{Client, Url};
use scraper::{Html, Selector};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct Finding { cat: &'static str, title: String, status: &'static str, sev: &'static str, detail: String, steps: Vec<String> }
#[derive(Serialize)]
struct Report { url: String, status: u16, ms: u64, scores: [u32; 3], total: u32, findings: Vec<Finding> }

// ok: Some(true)=uygun, Some(false)=eksik, None=uyarı
fn add(v: &mut Vec<Finding>, cat: &'static str, sev: &'static str, ok: Option<bool>, title: &str, detail: impl Into<String>, steps: &[&str]) {
    let status = match ok { Some(true) => "pass", Some(false) => "fail", None => "warn" };
    let steps = if status == "pass" { vec![] } else { steps.iter().map(|s| s.to_string()).collect() };
    v.push(Finding { cat, title: title.into(), status, sev, detail: detail.into(), steps });
}
fn sel(s: &str) -> Selector { Selector::parse(s).unwrap() }

const BOTS: [&str; 7] = ["gptbot", "claudebot", "anthropic-ai", "google-extended", "perplexitybot", "ccbot", "bytespider"];
fn blocked_bots(t: &str) -> Vec<&'static str> {
    let (mut agents, mut last_rule, mut out): (Vec<String>, bool, Vec<&'static str>) = (vec![], false, vec![]);
    for l in t.lines() {
        let l = l.split('#').next().unwrap_or("").trim().to_lowercase();
        if let Some(a) = l.strip_prefix("user-agent:") {
            if last_rule { agents.clear(); last_rule = false; }
            agents.push(a.trim().to_string());
        } else if let Some(r) = l.strip_prefix("disallow:") {
            last_rule = true;
            if r.trim() == "/" {
                for a in &agents { for b in BOTS { if (a.as_str() == b || a == "*") && !out.contains(&b) { out.push(b); } } }
            }
        } else if l.starts_with("allow:") { last_rule = true; }
    }
    out
}

fn header_checks(h: &reqwest::header::HeaderMap, https: bool, o: &mut Vec<Finding>) {
    let hv = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    add(o, "sec", "high", Some(https), "HTTPS kullanımı", "Site şifresiz HTTP üzerinden sunuluyor.", &[
        "Bir TLS sertifikası edinin (Let’s Encrypt ücretsizdir: `certbot --nginx`).",
        "Tüm HTTP isteklerini 301 ile HTTPS’e yönlendirin."]);
    add(o, "sec", "med", Some(hv("strict-transport-security").is_some()), "HSTS başlığı", "Tarayıcıya yalnızca HTTPS kullanmasını söyleyen başlık yok.", &[
        "Yanıta `Strict-Transport-Security: max-age=31536000; includeSubDomains` ekleyin.",
        "Önce kısa bir süreyle (`max-age=300`) deneyin, sorun yoksa artırın."]);
    let csp = hv("content-security-policy");
    let (ok, d) = match &csp {
        None => (Some(false), "CSP yok. XSS’e karşı en güçlü ikinci savunma hattı eksik.".to_string()),
        Some(c) if c.contains("unsafe-inline") || c.contains("unsafe-eval") => (None, "CSP var ama `unsafe-inline` / `unsafe-eval` içeriyor; XSS korumasını zayıflatır.".into()),
        _ => (Some(true), String::new()),
    };
    add(o, "sec", "high", ok, "Content-Security-Policy (XSS koruması)", d, &[
        "Önce `Content-Security-Policy-Report-Only: default-src 'self'` ile izleme moduna alın.",
        "Kullandığınız dış kaynakları (CDN, analitik) açıkça listeleyin.",
        "`unsafe-inline` yerine nonce veya hash kullanın.",
        "Raporlar temizlenince başlığı zorunlu moda çevirin."]);
    let fa = hv("x-frame-options").is_some() || csp.as_deref().map_or(false, |c| c.contains("frame-ancestors"));
    add(o, "sec", "med", Some(fa), "Clickjacking koruması", "Sayfa başka sitelerin içine gömülebilir.", &[
        "`X-Frame-Options: DENY` ekleyin ya da CSP’de `frame-ancestors 'none'` kullanın."]);
    add(o, "sec", "low", Some(hv("x-content-type-options").is_some()), "X-Content-Type-Options", "MIME sniffing kapatılmamış.", &["`X-Content-Type-Options: nosniff` başlığını ekleyin."]);
    add(o, "sec", "low", Some(hv("referrer-policy").is_some()), "Referrer-Policy", "Gelen/giden bağlantılarda tam adres sızabilir.", &["`Referrer-Policy: strict-origin-when-cross-origin` ekleyin."]);
    add(o, "sec", "low", Some(hv("permissions-policy").is_some()), "Permissions-Policy", "Kamera, mikrofon, konum gibi özellikler kısıtlanmamış.", &["`Permissions-Policy: camera=(), microphone=(), geolocation=()` ekleyin."]);
    let weak: Vec<String> = h.get_all("set-cookie").iter().filter_map(|c| c.to_str().ok()).filter(|c| {
        let l = c.to_lowercase(); !(l.contains("secure") && l.contains("httponly") && l.contains("samesite"))
    }).map(|c| c.split('=').next().unwrap_or("?").to_string()).collect();
    add(o, "sec", "high", Some(weak.is_empty()), "Çerez bayrakları", format!("Eksik bayrak: {}", weak.join(", ")), &[
        "Çerezleri `Set-Cookie: sid=...; Secure; HttpOnly; SameSite=Lax` biçiminde gönderin.",
        "Framework’ünüzün oturum ayarlarında bu üç bayrağı açın."]);
    let leak = [hv("server").filter(|s| s.chars().any(|c| c.is_ascii_digit())), hv("x-powered-by")].into_iter().flatten().collect::<Vec<_>>();
    add(o, "sec", "low", Some(leak.is_empty()), "Sürüm bilgisi sızıntısı", format!("Başlıklar teknolojiyi açık ediyor: {}", leak.join(", ")), &[
        "nginx: `server_tokens off;` — Apache: `ServerTokens Prod`.", "`X-Powered-By` başlığını kaldırın."]);
    add(o, "sec", "med", Some(hv("access-control-allow-origin").as_deref() != Some("*")), "CORS politikası", "`Access-Control-Allow-Origin: *` her siteye izin veriyor.", &["Joker (`*`) yerine yalnızca güvendiğiniz kökenleri tek tek yazın."]);
}

fn html_checks(body: &str, base: &Url, o: &mut Vec<Finding>) {
    let d = Html::parse_document(body);
    let low = body.to_lowercase();
    let https = base.scheme() == "https";
    let has = |ks: &[&str]| ks.iter().any(|k| low.contains(k));
    if https {
        let n = d.select(&sel("script[src],img[src],iframe[src],link[rel=stylesheet]")).filter(|e| {
            e.value().attr("src").or(e.value().attr("href")).unwrap_or("").starts_with("http://") }).count();
        add(o, "sec", "med", Some(n == 0), "Karışık içerik", format!("{n} kaynak HTTP ile yükleniyor."), &["Tüm kaynak adreslerini `https://` yapın veya göreli yola çevirin."]);
    } else if d.select(&sel("input[type=password]")).next().is_some() {
        add(o, "sec", "high", Some(false), "Şifre alanı HTTP üzerinde", "Parolalar açık metin gidiyor.", &["Siteyi HTTPS’e taşıyın."]);
    }
    let on = d.select(&sel("*")).filter(|e| e.value().attrs().any(|(k, _)| k.starts_with("on"))).count();
    add(o, "sec", "med", Some(on == 0), "Satır içi olay işleyicileri (XSS yüzeyi)", format!("{on} öğede `onclick=` benzeri nitelik var."), &[
        "Bunları `addEventListener` ile ayrı bir JS dosyasına taşıyın.", "Böylece CSP’den `unsafe-inline` kaldırılabilir."]);
    let sinks = d.select(&sel("script:not([src])")).filter(|e| { let t = e.text().collect::<String>(); t.contains("innerHTML") || t.contains("document.write") || t.contains("eval(") }).count();
    add(o, "sec", "med", if sinks == 0 { Some(true) } else { None }, "Riskli DOM işlemleri (DOM-XSS)", format!("{sinks} satır içi betikte `innerHTML`/`document.write`/`eval` geçiyor. Kullanıcı verisi bunlara ulaşıyorsa XSS oluşur."), &[
        "`innerHTML` yerine `textContent` kullanın.", "HTML gerekiyorsa DOMPurify ile temizleyin.", "`eval` ve `document.write` kullanmayın."]);
    let host = base.host_str().unwrap_or("");
    let nosri = d.select(&sel("script[src]")).filter(|e| e.value().attr("integrity").is_none()
        && base.join(e.value().attr("src").unwrap()).ok().map_or(false, |u| u.host_str().unwrap_or("") != host)).count();
    add(o, "sec", "med", Some(nosri == 0), "Dış betiklerde SRI", format!("{nosri} üçüncü taraf betik bütünlük doğrulaması olmadan yükleniyor."), &[
        "`<script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\">` ekleyin.",
        "Hash: `openssl dgst -sha384 -binary dosya.js | openssl base64 -A`."]);

    // Mevzuat
    add(o, "legal", "high", Some(has(&["gizlilik", "privacy", "kvkk", "aydınlatma", "kişisel veri", "gdpr"])), "Gizlilik / KVKK aydınlatma metni", "Sayfada bağlantı veya ifade bulunamadı.", &[
        "6698 sayılı KVKK m.10 uyarınca Aydınlatma Metni hazırlayın: veri sorumlusu, işleme amacı, aktarım, haklarınız.",
        "Footer’a her sayfadan erişilen bir bağlantı koyun."]);
    add(o, "legal", "high", Some(has(&["çerez", "cerez", "cookie", "consent"])), "Çerez bildirimi ve rıza", "Çerez politikası veya rıza banner’ı tespit edilemedi.", &[
        "Zorunlu olmayan çerezlerden önce açık rıza alan bir banner ekleyin; Kabul ve Reddet eşit görünür olsun.",
        "Ayrı bir Çerez Politikası sayfası yayımlayın."]);
    add(o, "legal", "med", Some(has(&["kullanım koşul", "kullanim kosul", "terms", "şartlar", "sözleşme", "sozlesme"])), "Kullanım koşulları", "Koşullar sayfasına işaret yok.", &["Hizmetin kapsamını ve sorumluluk sınırlarını anlatan bir Kullanım Koşulları sayfası ekleyin."]);
    add(o, "legal", "med", Some(has(&["iletişim", "iletisim", "contact", "mailto:", "tel:"])), "İletişim ve ticari bilgiler", "Unvan/iletişim bilgisi bulunamadı.", &["Unvan, adres, e-posta ve telefonu iletişim sayfasında yayımlayın (E-Ticaret Kanunu ve ETBİS yükümlülükleri)."]);
    if has(&["sepet", "cart", "checkout"]) {
        add(o, "legal", "high", Some(has(&["mesafeli", "cayma", "iade", "refund", "return"])), "Mesafeli satış ve iade", "Alışveriş öğeleri var ama cayma/iade metni yok.", &["Mesafeli Sözleşmeler Yönetmeliği gereği ön bilgilendirme formu, 14 gün cayma hakkı ve iade koşullarını yayımlayın."]);
    }
    let lang = d.select(&sel("html")).next().and_then(|e| e.value().attr("lang")).is_some();
    add(o, "legal", "low", Some(lang), "Dil bildirimi (erişilebilirlik)", "`<html lang>` yok.", &["`<html lang=\"tr\">` ekleyin; ekran okuyucular doğru dili seçer."]);
    let (imgs, noalt) = (d.select(&sel("img")).count(), d.select(&sel("img:not([alt])")).count());
    add(o, "legal", "low", Some(noalt == 0), "Görsel alternatif metinleri", format!("{imgs} görselin {noalt} tanesinde `alt` yok."), &["Her anlamlı görsele `alt` yazın; süs görsellerde `alt=\"\"` kullanın."]);

    // Yapay zekâ görünürlüğü
    let title = d.select(&sel("title")).next().map(|t| t.text().collect::<String>()).unwrap_or_default();
    add(o, "ai", "high", Some(!title.trim().is_empty()), "Sayfa başlığı", "`<title>` boş veya yok.", &["Sayfayı tek cümlede anlatan, benzersiz bir `<title>` yazın."]);
    let desc = d.select(&sel("meta[name=description]")).next().and_then(|m| m.value().attr("content")).unwrap_or("");
    add(o, "ai", "med", Some(!desc.trim().is_empty()), "Meta açıklama", "Özet açıklama yok.", &["`<meta name=\"description\" content=\"...\">` ile 150 karakterlik özet ekleyin."]);
    let h1 = d.select(&sel("h1")).count();
    add(o, "ai", "med", if h1 == 1 { Some(true) } else if h1 == 0 { Some(false) } else { None }, "Tek bir h1", format!("{h1} adet h1 bulundu."), &["Sayfada ana konuyu belirten tam bir `<h1>` bırakın; alt başlıklar için h2–h3 kullanın."]);
    add(o, "ai", "med", Some(d.select(&sel("main,article")).next().is_some()), "Anlamsal yapı", "`<main>` / `<article>` yok; yapay zekâ ana içeriği ayıramaz.", &["İçeriği `<header> <nav> <main> <footer>` etiketleriyle sarın."]);
    add(o, "ai", "med", Some(d.select(&sel("script[type=\"application/ld+json\"]")).next().is_some()), "Yapılandırılmış veri (JSON-LD)", "schema.org işaretlemesi yok.", &["Kuruluş/ürün/makale için `<script type=\"application/ld+json\">` ekleyin.", "Sonucu Google Rich Results Test ile doğrulayın."]);
    add(o, "ai", "low", Some(d.select(&sel("link[rel=canonical]")).next().is_some()), "Canonical adres", "Kanonik bağlantı yok.", &["`<link rel=\"canonical\" href=\"...\">` ekleyin."]);
    let noidx = d.select(&sel("meta[name=robots]")).any(|m| m.value().attr("content").unwrap_or("").contains("noindex"));
    add(o, "ai", "high", Some(!noidx), "noindex etiketi", "Sayfa arama ve yapay zekâ dizinlerinden gizlenmiş.", &["Gizlemek istemiyorsanız `noindex` değerini kaldırın."]);
    let words: usize = d.select(&sel("p,h1,h2,h3,li")).map(|e| e.text().collect::<String>().split_whitespace().count()).sum();
    add(o, "ai", "high", if words >= 80 { Some(true) } else { None }, "HTML’de okunabilir metin", format!("İlk yanıtta yalnızca ~{words} kelime var. İçerik JavaScript ile sonradan yükleniyorsa yapay zekâ botları boş sayfa görür."), &[
        "Önemli içeriği sunucu tarafında üretin (SSR / statik üretim).", "`curl` ile sayfayı çekip içeriğin gelip gelmediğini kontrol edin."]);
}

async fn fetch(c: &Client, base: &Url, p: &str) -> Option<String> {
    let r = c.get(base.join(p).ok()?).send().await.ok()?;
    if !r.status().is_success() { return None; }
    let t = r.text().await.ok()?;
    if t.trim_start().starts_with('<') { None } else { Some(t) }
}

fn score(f: &[Finding], cat: &str) -> u32 {
    let (mut g, mut t) = (0.0, 0.0);
    for x in f.iter().filter(|x| x.cat == cat) {
        let w = match x.sev { "high" => 3.0, "med" => 2.0, _ => 1.0 };
        t += w; g += match x.status { "pass" => w, "warn" => w * 0.5, _ => 0.0 };
    }
    if t == 0.0 { 100 } else { (g / t * 100.0_f64).round() as u32 }
}

// Yalnızca pasif analiz: tek GET isteği + robots/llms/sitemap. Saldırı payload’ı gönderilmez.
#[tauri::command]
async fn scan(url: String) -> Result<Report, String> {
    let mut u = url.trim().to_string();
    if !u.contains("://") { u = format!("https://{u}"); }
    let parsed = Url::parse(&u).map_err(|_| "Geçersiz adres. Örnek: ornek.com".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") { return Err("Yalnızca http ve https desteklenir.".into()); }
    let c = Client::builder().user_agent("Webbde/0.1 (pasif analiz)").timeout(Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let t = Instant::now();
    let r = c.get(parsed).send().await.map_err(|e| format!("Siteye ulaşılamadı: {e}"))?;
    let ms = t.elapsed().as_millis() as u64;
    let (status, fin, h) = (r.status().as_u16(), r.url().clone(), r.headers().clone());
    let body = r.text().await.unwrap_or_default();
    let mut f = Vec::new();
    header_checks(&h, fin.scheme() == "https", &mut f);
    html_checks(&body, &fin, &mut f);

    let robots = fetch(&c, &fin, "/robots.txt").await;
    add(&mut f, "ai", "med", Some(robots.is_some()), "robots.txt", "Dosya bulunamadı.", &["Kök dizine `robots.txt` ekleyin ve `Sitemap:` satırını yazın."]);
    if let Some(rb) = &robots {
        let b = blocked_bots(rb);
        add(&mut f, "ai", "med", if b.is_empty() { Some(true) } else { None }, "Yapay zekâ botlarına erişim", format!("Engellenen botlar: {}", b.join(", ")), &[
            "Yapay zekâ araçlarında görünmek istiyorsanız ilgili `Disallow: /` satırlarını kaldırın.", "Bilinçli bir tercihse bu bir hata değildir."]);
    }
    add(&mut f, "ai", "low", Some(fetch(&c, &fin, "/llms.txt").await.is_some()), "llms.txt", "Yapay zekâ için site özeti dosyası yok.", &["Kök dizine Markdown biçiminde `llms.txt` ekleyin: başlık, kısa özet, önemli sayfa bağlantıları."]);
    let sm = robots.as_deref().map_or(false, |r| r.to_lowercase().contains("sitemap:")) || fetch(&c, &fin, "/sitemap.xml").await.is_some();
    add(&mut f, "ai", "med", Some(sm), "Site haritası", "sitemap.xml bulunamadı.", &["Sitenizin sayfalarını listeleyen `sitemap.xml` üretin."]);

    let scores = [score(&f, "sec"), score(&f, "legal"), score(&f, "ai")];
    let total = scores.iter().sum::<u32>() / 3;
    Ok(Report { url: fin.to_string(), status, ms, scores, total, findings: f })
}

fn main() {
    tauri::Builder::default().invoke_handler(tauri::generate_handler![scan]).run(tauri::generate_context!()).expect("Webbde başlatılamadı");
}
