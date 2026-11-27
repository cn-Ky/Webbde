// Webbde tarama çekirdeği. Yalnızca pasif istekler: normal ziyaretçi GET'leri, robots.txt'e uyan nazik tarama.
// Saldırı verisi (payload) göndermez, hassas dosya yollarını (.env, .git vb.) yoklamaz.
use reqwest::{header::HeaderMap, Client, Url};
use scraper::{Html, Selector};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const UA: &str = "Webbde/0.2 (pasif analiz)";
// "Tüm site" modunda güvenlik tavanı: kontrolsüz sonsuz sitelerde (takvim, filtre vb.) tarama sonsuza gitmesin.
const SITE_MAX: usize = 5000;
const SEEN_MAX: usize = 100_000;
const CORPUS_MAX: usize = 3_000_000;

#[derive(Serialize)]
pub struct Finding { cat: &'static str, title: String, status: &'static str, sev: &'static str, detail: String, refs: String, steps: Vec<String> }
#[derive(Serialize)]
pub struct PageInfo { url: String, status: u16, ms: u64, bytes: usize, title: String, words: usize, issues: Vec<String> }
#[derive(Serialize, Default)]
pub struct AiView { title: String, description: String, outline: Vec<String>, text: String, words: usize, links: usize, images: usize, schema: Vec<String> }
#[derive(Serialize)]
pub struct CookieInfo { name: String, secure: bool, httponly: bool, samesite: String }
#[derive(Serialize)]
pub struct Tech { name: String, version: String, note: String }
#[derive(Serialize)]
pub struct Tls { issuer: String, subject: String, expires: String, days_left: i64 }
#[derive(Serialize)]
pub struct Report {
    url: String, status: u16, ms: u64, bytes: usize, scores: [u32; 4], total: u32,
    findings: Vec<Finding>, pages: Vec<PageInfo>, ai_view: AiView, bots: Vec<(String, bool)>,
    headers: Vec<(String, String)>, cookies: Vec<CookieInfo>, tech: Vec<Tech>, trackers: Vec<String>,
    tls: Option<Tls>, dns: Vec<(String, String)>,
    // Tarama kapsamı: kuyrukta taranmadan kalan sayfa sayısı ve kullanıcı durdurdu mu
    left: usize, cancelled: bool,
}

// ok: Some(true)=uygun, Some(false)=eksik, None=uyarı
fn add(v: &mut Vec<Finding>, cat: &'static str, sev: &'static str, ok: Option<bool>, title: &str, detail: impl Into<String>, refs: &str, steps: &[&str]) {
    let status = match ok { Some(true) => "pass", Some(false) => "fail", None => "warn" };
    let steps = if status == "pass" { vec![] } else { steps.iter().map(|s| s.to_string()).collect() };
    v.push(Finding { cat, title: title.into(), status, sev, detail: detail.into(), refs: refs.into(), steps });
}
fn sel(s: &str) -> Selector { Selector::parse(s).unwrap() }
fn hv(h: &HeaderMap, n: &str) -> Option<String> { h.get(n).and_then(|v| v.to_str().ok()).map(|s| s.to_string()) }
fn clip(s: &str, n: usize) -> String { s.chars().take(n).collect() }
fn flat(s: &str) -> String { s.split_whitespace().collect::<Vec<_>>().join(" ") }
fn vparse(s: &str) -> Vec<u32> { s.split('.').map(|x| x.parse().unwrap_or(0)).collect() }
fn vlt(a: &str, b: &str) -> bool { vparse(a) < vparse(b) }

const BOTS: [&str; 8] = ["gptbot", "chatgpt-user", "claudebot", "anthropic-ai", "google-extended", "perplexitybot", "ccbot", "bytespider"];
const TRACK: [(&str, &str); 12] = [("google-analytics.com", "Google Analytics"), ("googletagmanager.com", "Google Tag Manager"), ("connect.facebook.net", "Meta Pixel"), ("facebook.com/tr", "Meta Pixel"),
    ("hotjar.com", "Hotjar"), ("clarity.ms", "Microsoft Clarity"), ("doubleclick.net", "Google Ads"), ("googleadservices.com", "Google Ads"), ("analytics.tiktok.com", "TikTok Pixel"),
    ("snap.licdn.com", "LinkedIn Insight"), ("mc.yandex.ru", "Yandex Metrica"), ("criteo.", "Criteo")];
const THIRD: [(&str, &str); 3] = [("fonts.googleapis.com", "Google Fonts"), ("youtube.com/embed", "YouTube gömme"), ("maps.googleapis.com", "Google Maps")];
const CMPS: [&str; 12] = ["cookiebot", "onetrust", "iubenda", "cookieyes", "klaro", "complianz", "cookie-law-info", "osano", "usercentrics", "borlabs", "cookieconsent", "çerez tercih"];

fn robots_groups(t: &str) -> (Vec<&'static str>, Vec<String>) {
    let (mut agents, mut last_rule, mut blocked, mut star): (Vec<String>, bool, Vec<&'static str>, Vec<String>) = (vec![], false, vec![], vec![]);
    for l in t.lines() {
        let l = l.split('#').next().unwrap_or("").trim().to_lowercase();
        if let Some(a) = l.strip_prefix("user-agent:") {
            if last_rule { agents.clear(); last_rule = false; }
            agents.push(a.trim().to_string());
        } else if let Some(r) = l.strip_prefix("disallow:") {
            last_rule = true;
            let r = r.trim().to_string();
            if r.is_empty() { continue; }
            if agents.iter().any(|a| a == "*") { star.push(r.clone()); }
            if r == "/" { for a in &agents { for b in BOTS { if (a.as_str() == b || a == "*") && !blocked.contains(&b) { blocked.push(b); } } } }
        } else if l.starts_with("allow:") { last_rule = true; }
    }
    (blocked, star)
}

struct Cert; impl Cert {
    fn parse(der: &[u8]) -> Option<Tls> {
        let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
        let na = c.validity().not_after.timestamp();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
        Some(Tls { issuer: c.issuer().to_string(), subject: c.subject().to_string(), expires: c.validity().not_after.to_string(), days_left: (na - now) / 86400 })
    }
}

fn header_checks(h: &HeaderMap, https: bool, o: &mut Vec<Finding>) -> Vec<CookieInfo> {
    add(o, "sec", "high", Some(https), "HTTPS kullanımı", "Site şifresiz HTTP üzerinden sunuluyor.", "CWE-319 · OWASP A02:2021", &[
        "Bir TLS sertifikası edinin (Let’s Encrypt ücretsizdir: `certbot --nginx`).", "Tüm HTTP isteklerini 301 ile HTTPS’e yönlendirin."]);
    add(o, "sec", "med", Some(hv(h, "strict-transport-security").is_some()), "HSTS başlığı", "Tarayıcıya yalnızca HTTPS kullanmasını söyleyen başlık yok.", "OWASP A05:2021", &[
        "Yanıta `Strict-Transport-Security: max-age=31536000; includeSubDomains` ekleyin.", "Önce kısa bir süreyle (`max-age=300`) deneyin, sorun yoksa artırın."]);
    let csp = hv(h, "content-security-policy");
    let (ok, d) = match &csp {
        None => (Some(false), "CSP yok. XSS’e karşı en güçlü ikinci savunma hattı eksik.".to_string()),
        Some(c) if c.contains("unsafe-inline") || c.contains("unsafe-eval") => (None, format!("CSP `unsafe-inline`/`unsafe-eval` içeriyor: {}", clip(c, 160))),
        _ => (Some(true), String::new()),
    };
    add(o, "sec", "high", ok, "Content-Security-Policy (XSS koruması)", d, "CWE-79 · OWASP A03:2021", &[
        "Önce `Content-Security-Policy-Report-Only: default-src 'self'` ile izleme moduna alın.", "Kullandığınız dış kaynakları (CDN, analitik) açıkça listeleyin.",
        "`unsafe-inline` yerine nonce veya hash kullanın.", "Raporlar temizlenince başlığı zorunlu moda çevirin."]);
    let fa = hv(h, "x-frame-options").is_some() || csp.as_deref().map_or(false, |c| c.contains("frame-ancestors"));
    add(o, "sec", "med", Some(fa), "Clickjacking koruması", "Sayfa başka sitelerin içine gömülebilir.", "CWE-1021", &["`X-Frame-Options: DENY` ekleyin ya da CSP’de `frame-ancestors 'none'` kullanın."]);
    add(o, "sec", "low", Some(hv(h, "x-content-type-options").is_some()), "X-Content-Type-Options", "MIME sniffing kapatılmamış.", "CWE-430", &["`X-Content-Type-Options: nosniff` başlığını ekleyin."]);
    add(o, "sec", "low", Some(hv(h, "referrer-policy").is_some()), "Referrer-Policy", "Giden bağlantılarda tam adres sızabilir.", "CWE-200", &["`Referrer-Policy: strict-origin-when-cross-origin` ekleyin."]);
    add(o, "sec", "low", Some(hv(h, "permissions-policy").is_some()), "Permissions-Policy", "Kamera, mikrofon, konum gibi özellikler kısıtlanmamış.", "OWASP A05:2021", &["`Permissions-Policy: camera=(), microphone=(), geolocation=()` ekleyin."]);
    let cookies: Vec<CookieInfo> = h.get_all("set-cookie").iter().filter_map(|c| c.to_str().ok()).map(|c| {
        let l = c.to_lowercase();
        let ss = l.split("samesite=").nth(1).map(|x| x.split(';').next().unwrap_or("").trim().to_string()).unwrap_or_default();
        CookieInfo { name: c.split('=').next().unwrap_or("?").to_string(), secure: l.contains("secure"), httponly: l.contains("httponly"), samesite: ss }
    }).collect();
    let weak: Vec<String> = cookies.iter().filter(|c| !(c.secure && c.httponly && !c.samesite.is_empty())).map(|c| c.name.clone()).collect();
    add(o, "sec", "high", Some(weak.is_empty()), "Çerez bayrakları", format!("Eksik bayrak: {}", weak.join(", ")), "CWE-614 · CWE-1004", &[
        "Çerezleri `Set-Cookie: sid=...; Secure; HttpOnly; SameSite=Lax` biçiminde gönderin.", "Framework’ünüzün oturum ayarlarında bu üç bayrağı açın."]);
    let leak: Vec<String> = [hv(h, "server").filter(|s| s.chars().any(|c| c.is_ascii_digit())), hv(h, "x-powered-by")].into_iter().flatten().collect();
    add(o, "sec", "low", Some(leak.is_empty()), "Sürüm bilgisi sızıntısı", format!("Başlıklar teknolojiyi açık ediyor: {}", leak.join(", ")), "CWE-200", &["nginx: `server_tokens off;` — Apache: `ServerTokens Prod`.", "`X-Powered-By` başlığını kaldırın."]);
    add(o, "sec", "med", Some(hv(h, "access-control-allow-origin").as_deref() != Some("*")), "CORS politikası", "`Access-Control-Allow-Origin: *` her siteye izin veriyor.", "CWE-942", &["Joker (`*`) yerine yalnızca güvendiğiniz kökenleri tek tek yazın."]);
    cookies
}

fn ver(srcs: &[String], name: &str) -> Option<String> {
    for s in srcs {
        let mut from = 0;
        while let Some(i) = s[from..].find(name) {
            let a = from + i + name.len();
            let rest = &s[a..];
            let rest = rest.strip_prefix(|c: char| "-/@.".contains(c)).unwrap_or(rest);
            if rest.starts_with(|c: char| c.is_ascii_digit()) {
                let v: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                let v = v.trim_end_matches('.').to_string();
                if v.contains('.') { return Some(v); }
            }
            from = a;
        }
    }
    None
}
fn jtypes(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| jtypes(x, out)),
        Value::Object(m) => {
            match m.get("@type") { Some(Value::String(s)) => out.push(s.clone()), Some(Value::Array(a)) => { for x in a { if let Some(s) = x.as_str() { out.push(s.into()); } } } _ => {} }
            if let Some(g) = m.get("@graph") { jtypes(g, out); }
        }
        _ => {}
    }
}

struct HtmlOut { ai: AiView, tech: Vec<Tech>, trackers: Vec<String>, tracking: bool, thirds: Vec<String> }

fn html_checks(body: &str, base: &Url, h: &HeaderMap, o: &mut Vec<Finding>) -> HtmlOut {
    let d = Html::parse_document(body);
    let low = body.to_lowercase();
    let https = base.scheme() == "https";
    let host = base.host_str().unwrap_or("").to_string();
    let txt = |e: scraper::ElementRef| e.text().collect::<String>();

    // --- Güvenlik: kaynaklar, betikler
    if https {
        let n = d.select(&sel("script[src],img[src],iframe[src],link[rel=stylesheet]")).filter(|e| e.value().attr("src").or(e.value().attr("href")).unwrap_or("").starts_with("http://")).count();
        add(o, "sec", "med", Some(n == 0), "Karışık içerik", format!("{n} kaynak HTTP ile yükleniyor."), "CWE-311", &["Tüm kaynak adreslerini `https://` yapın veya göreli yola çevirin."]);
    } else if d.select(&sel("input[type=password]")).next().is_some() {
        add(o, "sec", "high", Some(false), "Şifre alanı HTTP üzerinde", "Parolalar açık metin gidiyor.", "CWE-319", &["Siteyi HTTPS’e taşıyın."]);
    }
    let on = d.select(&sel("*")).filter(|e| e.value().attrs().any(|(k, _)| k.starts_with("on"))).count();
    add(o, "sec", "med", Some(on == 0), "Satır içi olay işleyicileri (XSS yüzeyi)", format!("{on} öğede `onclick=` benzeri nitelik var."), "CWE-79", &["Bunları `addEventListener` ile ayrı bir JS dosyasına taşıyın.", "Böylece CSP’den `unsafe-inline` kaldırılabilir."]);
    let sinks = d.select(&sel("script:not([src])")).filter(|e| { let t = txt(*e); t.contains("innerHTML") || t.contains("document.write") || t.contains("eval(") }).count();
    add(o, "sec", "med", if sinks == 0 { Some(true) } else { None }, "Riskli DOM işlemleri (DOM-XSS)", format!("{sinks} satır içi betikte `innerHTML`/`document.write`/`eval` geçiyor. Kullanıcı verisi bunlara ulaşıyorsa XSS oluşur."), "CWE-79", &["`innerHTML` yerine `textContent` kullanın.", "HTML gerekiyorsa DOMPurify ile temizleyin.", "`eval` ve `document.write` kullanmayın."]);
    let nosri = d.select(&sel("script[src]")).filter(|e| e.value().attr("integrity").is_none() && base.join(e.value().attr("src").unwrap()).ok().map_or(false, |u| u.host_str().unwrap_or("") != host)).count();
    add(o, "sec", "med", Some(nosri == 0), "Dış betiklerde SRI", format!("{nosri} üçüncü taraf betik bütünlük doğrulaması olmadan yükleniyor."), "CWE-829 · OWASP A08:2021", &["`<script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\">` ekleyin.", "Hash: `openssl dgst -sha384 -binary dosya.js | openssl base64 -A`."]);
    let blank = d.select(&sel("a[target=_blank]")).filter(|a| !a.value().attr("rel").unwrap_or("").contains("noopener") && !a.value().attr("rel").unwrap_or("").contains("noreferrer")).count();
    add(o, "sec", "low", Some(blank == 0), "target=_blank bağlantıları", format!("{blank} bağlantıda `rel=\"noopener\"` yok."), "CWE-1022", &["Bu bağlantılara `rel=\"noopener noreferrer\"` ekleyin."]);

    // --- Formlar (pasif)
    let (mut nocsrf, mut httpact, mut pwget, mut cross, mut forms) = (0, 0, 0, vec![], 0);
    for f in d.select(&sel("form")) {
        forms += 1;
        let m = f.value().attr("method").unwrap_or("get").to_lowercase();
        if let Ok(a) = base.join(f.value().attr("action").unwrap_or("")) {
            if https && a.scheme() == "http" { httpact += 1; }
            if a.host_str().map_or(false, |x| x != host.as_str()) { cross.push(a.host_str().unwrap_or("").to_string()); }
        }
        if m == "get" && f.select(&sel("input[type=password]")).next().is_some() { pwget += 1; }
        if m == "post" && !f.select(&sel("input[type=hidden]")).any(|i| { let n = i.value().attr("name").unwrap_or("").to_lowercase(); ["csrf", "token", "nonce", "authenticity", "verification"].iter().any(|k| n.contains(k)) }) { nocsrf += 1; }
    }
    if forms > 0 {
        add(o, "sec", "high", Some(httpact == 0 && pwget == 0), "Form güvenliği", format!("{httpact} form HTTP adresine gönderiyor, {pwget} formda parola GET ile gidiyor."), "CWE-319 · CWE-598", &["Form `action` adreslerini HTTPS yapın.", "Parola alanı olan formlarda `method=\"post\"` kullanın."]);
        add(o, "sec", "med", if nocsrf == 0 { Some(true) } else { None }, "CSRF belirteci", format!("{nocsrf} POST formunda CSRF belirteci görünmüyor (SameSite çerez veya başlık tabanlı koruma kullanılıyor olabilir)."), "CWE-352", &["Framework’ün CSRF ara katmanını açın ve her POST formuna gizli belirteç ekleyin.", "Çerezlerde `SameSite=Lax/Strict` kullanın."]);
        add(o, "sec", "low", if cross.is_empty() { Some(true) } else { None }, "Başka alana veri gönderen form", format!("Form hedefleri: {}", cross.join(", ")), "CWE-359", &["Hedef alanın güvenilir olduğundan ve aydınlatma metninde yazdığından emin olun."]);
    }
    // --- Yansıyan parametre (yalnızca verilen adresin kendi parametreleri; saldırı verisi gönderilmez)
    if base.query().is_some() {
        let refl: Vec<String> = base.query_pairs().filter(|(_, v)| v.len() >= 3 && body.contains(&**v)).map(|(k, _)| k.to_string()).collect();
        add(o, "sec", "med", if refl.is_empty() { Some(true) } else { None }, "Yansıyan URL parametreleri", format!("Şu parametrelerin değeri sayfada aynen görünüyor: {}", refl.join(", ")), "CWE-79", &["Bu değerleri çıktı bağlamına göre kodlayın (HTML, nitelik, JS ayrı ayrı).", "Şablon motorunun otomatik kaçışını (auto-escape) kapatmayın."]);
    }

    // --- Teknoloji ve eski kütüphaneler
    let srcs: Vec<String> = d.select(&sel("script[src],link[href]")).filter_map(|e| e.value().attr("src").or(e.value().attr("href"))).map(|s| s.to_lowercase()).collect();
    let mut tech: Vec<Tech> = vec![];
    let mut tp = |n: &str, v: &str, note: &str| tech.push(Tech { name: n.into(), version: v.into(), note: note.into() });
    if let Some(s) = hv(h, "server") { tp("Sunucu", &s, ""); }
    if let Some(s) = hv(h, "x-powered-by") { tp("X-Powered-By", &s, ""); }
    if let Some(g) = d.select(&sel("meta[name=generator]")).next().and_then(|m| m.value().attr("content")) { tp("Üretici", g, ""); }
    for (needle, name) in [("wp-content", "WordPress"), ("cdn.shopify.com", "Shopify"), ("/_next/", "Next.js"), ("/_nuxt/", "Nuxt"), ("wixstatic.com", "Wix"), ("drupal", "Drupal"), ("/media/jui/", "Joomla")] {
        if low.contains(needle) { tp(name, "", ""); }
    }
    if h.get("cf-ray").is_some() { tp("Cloudflare", "", ""); }
    let mut vuln: Vec<String> = vec![];
    if let Some(v) = ver(&srcs, "jquery") { let bad = vlt(&v, "3.5.0"); if bad { vuln.push(format!("jQuery {v}")); } tp("jQuery", &v, if bad { "XSS açıkları var (CVE-2020-11022/11023); 3.5.0+ kullanın" } else { "" }); }
    if let Some(v) = ver(&srcs, "bootstrap") { let mj: u32 = v.split('.').next().and_then(|x| x.parse().ok()).unwrap_or(9); let bad = mj < 3 || (mj == 3 && vlt(&v, "3.4.1")) || (mj == 4 && vlt(&v, "4.3.1")); if bad { vuln.push(format!("Bootstrap {v}")); } tp("Bootstrap", &v, if bad { "XSS açıkları var; güncelleyin" } else { "" }); }
    if let Some(v) = ver(&srcs, "lodash") { let bad = vlt(&v, "4.17.21"); if bad { vuln.push(format!("Lodash {v}")); } tp("Lodash", &v, if bad { "Prototype pollution açıkları var; 4.17.21+ kullanın" } else { "" }); }
    if let Some(v) = ver(&srcs, "angular") { if v.starts_with("1.") { vuln.push(format!("AngularJS {v}")); tp("AngularJS", &v, "Destek süresi doldu (EOL)"); } }
    add(o, "sec", "high", Some(vuln.is_empty()), "Güncel olmayan JavaScript kütüphaneleri", format!("Bilinen açıklı sürümler: {}", vuln.join(", ")), "CWE-1104 · OWASP A06:2021", &["Kütüphaneyi son kararlı sürüme yükseltin.", "`npm audit` veya `retire.js` ile bağımlılıklarınızı düzenli tarayın."]);

    // --- İzleyiciler (yasal bölümde değerlendirilir)
    let mut trackers: Vec<String> = TRACK.iter().filter(|(p, _)| low.contains(p)).map(|(_, n)| n.to_string()).collect();
    trackers.sort(); trackers.dedup();
    let mut thirds: Vec<String> = THIRD.iter().filter(|(p, _)| low.contains(p)).map(|(_, n)| n.to_string()).collect();
    thirds.sort(); thirds.dedup();

    // --- Yapay zekâ görünürlüğü
    let title = d.select(&sel("title")).next().map(txt).unwrap_or_default();
    add(o, "ai", "high", Some(!title.trim().is_empty()), "Sayfa başlığı", "`<title>` boş veya yok.", "Arama ve YZ özetleri", &["Sayfayı tek cümlede anlatan, benzersiz bir `<title>` yazın."]);
    let desc = d.select(&sel("meta[name=description]")).next().and_then(|m| m.value().attr("content")).unwrap_or("").to_string();
    add(o, "ai", "med", Some(!desc.trim().is_empty()), "Meta açıklama", "Özet açıklama yok.", "Arama ve YZ özetleri", &["`<meta name=\"description\" content=\"...\">` ile 150 karakterlik özet ekleyin."]);
    let h1 = d.select(&sel("h1")).count();
    add(o, "ai", "med", if h1 == 1 { Some(true) } else if h1 == 0 { Some(false) } else { None }, "Tek bir h1", format!("{h1} adet h1 bulundu."), "Anlamsal yapı", &["Ana konuyu belirten tek bir `<h1>` bırakın; alt başlıklar için h2–h3 kullanın."]);
    add(o, "ai", "med", Some(d.select(&sel("main,article")).next().is_some()), "Anlamsal yapı", "`<main>` / `<article>` yok; yapay zekâ ana içeriği ayıramaz.", "Anlamsal yapı", &["İçeriği `<header> <nav> <main> <footer>` etiketleriyle sarın."]);
    let mut schema = vec![];
    for s in d.select(&sel("script[type=\"application/ld+json\"]")) { if let Ok(v) = serde_json::from_str::<Value>(&txt(s)) { jtypes(&v, &mut schema); } }
    schema.sort(); schema.dedup();
    add(o, "ai", "med", Some(!schema.is_empty() || d.select(&sel("script[type=\"application/ld+json\"]")).next().is_some()), "Yapılandırılmış veri (JSON-LD)", "schema.org işaretlemesi yok.", "schema.org", &["Kuruluş/ürün/makale için `<script type=\"application/ld+json\">` ekleyin.", "Sonucu Google Rich Results Test ile doğrulayın."]);
    add(o, "ai", "low", Some(d.select(&sel("link[rel=canonical]")).next().is_some()), "Canonical adres", "Kanonik bağlantı yok.", "Yinelenen içerik", &["`<link rel=\"canonical\" href=\"...\">` ekleyin."]);
    let og = d.select(&sel("meta[property=\"og:title\"]")).next().is_some() && d.select(&sel("meta[property=\"og:description\"]")).next().is_some();
    add(o, "ai", "low", Some(og), "Sosyal paylaşım (Open Graph)", "`og:title` / `og:description` eksik; bağlantı önizlemeleri bozuk görünür.", "Open Graph", &["`<meta property=\"og:title\">` ve `og:description`, `og:image` ekleyin."]);
    let noidx = d.select(&sel("meta[name=robots]")).any(|m| m.value().attr("content").unwrap_or("").contains("noindex"));
    add(o, "ai", "high", Some(!noidx), "noindex etiketi", "Sayfa arama ve yapay zekâ dizinlerinden gizlenmiş.", "Dizinleme", &["Gizlemek istemiyorsanız `noindex` değerini kaldırın."]);
    let words: usize = d.select(&sel("p,h1,h2,h3,li")).map(|e| txt(e).split_whitespace().count()).sum();
    add(o, "ai", "high", if words >= 80 { Some(true) } else { None }, "HTML’de okunabilir metin", format!("İlk yanıtta yalnızca ~{words} kelime var. İçerik JavaScript ile sonradan yükleniyorsa yapay zekâ botları boş sayfa görür."), "Sunucu tarafı render", &["Önemli içeriği sunucu tarafında üretin (SSR / statik üretim).", "`curl` ile sayfayı çekip içeriğin gelip gelmediğini kontrol edin."]);

    // --- Kalite: erişilebilirlik
    add(o, "qual", "low", Some(d.select(&sel("html")).next().and_then(|e| e.value().attr("lang")).is_some()), "Dil bildirimi", "`<html lang>` yok.", "WCAG 3.1.1", &["`<html lang=\"tr\">` ekleyin; ekran okuyucular doğru dili seçer."]);
    add(o, "qual", "low", Some(d.select(&sel("meta[name=viewport]")).next().is_some()), "Mobil uyum (viewport)", "`viewport` etiketi yok.", "Mobil uyum", &["`<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">` ekleyin."]);
    let (imgs, noalt) = (d.select(&sel("img")).count(), d.select(&sel("img:not([alt])")).count());
    add(o, "qual", "med", Some(noalt == 0), "Görsel alternatif metinleri", format!("{imgs} görselin {noalt} tanesinde `alt` yok."), "WCAG 1.1.1", &["Her anlamlı görsele `alt` yazın; süs görsellerde `alt=\"\"` kullanın."]);
    let labels: HashSet<String> = d.select(&sel("label[for]")).filter_map(|l| l.value().attr("for")).map(|s| s.to_string()).collect();
    let unl = d.select(&sel("input:not([type=hidden]):not([type=submit]):not([type=button]),select,textarea")).filter(|i| {
        let v = i.value(); !(v.attr("aria-label").is_some() || v.attr("aria-labelledby").is_some() || v.attr("title").is_some() || v.attr("id").map_or(false, |id| labels.contains(id)))
    }).count();
    add(o, "qual", "med", Some(unl == 0), "Form alanı etiketleri", format!("{unl} alan etiketsiz."), "WCAG 1.3.1 · 3.3.2", &["Her alana `<label for=\"id\">` bağlayın veya `aria-label` verin."]);
    let nobtn = d.select(&sel("button")).filter(|b| txt(*b).trim().is_empty() && b.value().attr("aria-label").is_none() && b.value().attr("title").is_none()).count();
    let nolink = d.select(&sel("a[href]")).filter(|a| txt(*a).trim().is_empty() && a.value().attr("aria-label").is_none() && a.select(&sel("img[alt]")).next().is_none()).count();
    add(o, "qual", "med", Some(nobtn + nolink == 0), "Adsız düğme ve bağlantılar", format!("{nobtn} düğme, {nolink} bağlantı ekran okuyucuya isim vermiyor."), "WCAG 2.4.4 · 4.1.2", &["İkon düğmelere `aria-label=\"Menüyü aç\"` gibi açıklayıcı ad verin."]);
    let mut prev = 0; let mut skip = 0;
    for e in d.select(&sel("h1,h2,h3,h4,h5,h6")) { let l: i32 = e.value().name()[1..].parse().unwrap_or(0); if prev != 0 && l > prev + 1 { skip += 1; } prev = l; }
    add(o, "qual", "low", Some(skip == 0), "Başlık hiyerarşisi", format!("{skip} yerde başlık seviyesi atlanıyor (örn. h2’den h4’e)."), "WCAG 1.3.1", &["Başlıkları sırayla kullanın; boyut için CSS kullanın, seviye için değil."]);

    // --- Yapay zekânın gördüğü
    let outline: Vec<String> = d.select(&sel("h1,h2,h3,h4")).take(30).map(|e| format!("{} {}", e.value().name(), clip(&flat(&txt(e)), 90))).collect();
    let text = clip(&flat(&d.select(&sel("p,li,h1,h2,h3")).map(txt).collect::<Vec<_>>().join(" ")), 1200);
    let ai = AiView { title: flat(&title), description: desc, outline, text, words, links: d.select(&sel("a[href]")).count(), images: imgs, schema };
    HtmlOut { ai, tech, trackers, tracking: TRACK.iter().any(|(p, _)| low.contains(p)), thirds }
}

struct Facts { title: String, desc: bool, h1: usize, words: usize, anchors: Vec<(String, Url)> }
fn facts(body: &str, base: &Url) -> Facts {
    let d = Html::parse_document(body);
    let txt = |e: scraper::ElementRef| e.text().collect::<String>();
    Facts {
        title: flat(&d.select(&sel("title")).next().map(txt).unwrap_or_default()),
        desc: d.select(&sel("meta[name=description]")).next().and_then(|m| m.value().attr("content")).map_or(false, |c| !c.trim().is_empty()),
        h1: d.select(&sel("h1")).count(),
        words: d.select(&sel("p,h1,h2,h3,li")).map(|e| txt(e).split_whitespace().count()).sum(),
        anchors: d.select(&sel("a[href]")).filter_map(|a| { let u = base.join(a.value().attr("href")?).ok()?; Some((flat(&txt(a)).to_lowercase(), u)) }).collect(),
    }
}
fn text_low(body: &str) -> String {
    let d = Html::parse_document(body);
    d.select(&sel("p,li,h1,h2,h3,h4,h5,td,a,strong")).map(|e| e.text().collect::<String>()).collect::<Vec<_>>().join(" ").to_lowercase()
}
fn key(u: &Url) -> String { let mut x = u.clone(); x.set_fragment(None); x.to_string().trim_end_matches('/').to_string() }
fn crawlable(u: &Url) -> bool {
    let p = u.path().to_lowercase();
    u.query().is_none() && matches!(u.scheme(), "http" | "https")
        && ![".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".zip", ".css", ".js", ".xml", ".mp4", ".ico"].iter().any(|e| p.ends_with(e))
}
fn find_link(a: &[(String, Url)], ks: &[&str]) -> Option<Url> {
    a.iter().find(|(t, u)| ks.iter().any(|k| t.contains(k) || u.path().to_lowercase().contains(k))).map(|(_, u)| u.clone())
}
fn missing(t: &str, items: &[(&str, &[&str])]) -> Vec<String> {
    items.iter().filter(|(_, alts)| !alts.iter().any(|a| t.contains(a))).map(|(l, _)| l.to_string()).collect()
}
async fn get_body(c: &Client, u: &Url) -> Option<String> {
    let r = c.get(u.clone()).send().await.ok()?;
    if !r.status().is_success() { return None; }
    r.text().await.ok()
}
async fn fetch(c: &Client, base: &Url, p: &str) -> Option<String> {
    let t = get_body(c, &base.join(p).ok()?).await?;
    if t.trim_start().starts_with('<') { None } else { Some(t) }
}
fn locs(xml: &str) -> Vec<String> {
    let (mut out, mut rest) = (vec![], xml);
    while let Some(i) = rest.find("<loc>") {
        let after = &rest[i + 5..];
        let Some(j) = after.find("</loc>") else { break };
        out.push(after[..j].trim().trim_start_matches("<![CDATA[").trim_end_matches("]]>").replace("&amp;", "&"));
        rest = &after[j + 6..];
    }
    out
}
// robots.txt'teki Sitemap: satırları ve /sitemap.xml; sitemap index dosyalarının alt haritalarını da okur.
async fn sitemap_urls(c: &Client, base: &Url, robots: Option<&str>) -> Vec<Url> {
    let mut todo: Vec<Url> = vec![];
    for l in robots.unwrap_or("").lines() {
        let l = l.trim();
        if l.get(..8).map_or(false, |p| p.eq_ignore_ascii_case("sitemap:")) { if let Ok(u) = base.join(l[8..].trim()) { todo.push(u); } }
    }
    if let Ok(u) = base.join("/sitemap.xml") { if !todo.contains(&u) { todo.push(u); } }
    let (mut out, mut n) = (vec![], 0);
    while let Some(u) = todo.pop() {
        n += 1; if n > 50 { break; }
        let Some(x) = get_body(c, &u).await else { continue };
        if !(x.contains("<urlset") || x.contains("<sitemapindex")) { continue; }
        let idx = x.contains("<sitemapindex");
        for l in locs(&x) {
            let Ok(l) = Url::parse(&l) else { continue };
            if l.host_str() != base.host_str() { continue; }
            if idx { todo.push(l) } else { out.push(l) }
        }
        if out.len() > SEEN_MAX { break; }
    }
    out
}
async fn doh(c: &Client, name: &str, typ: &str) -> Vec<String> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type={typ}");
    let Ok(r) = c.get(&url).header("accept", "application/dns-json").send().await else { return vec![] };
    let Ok(v) = r.json::<Value>().await else { return vec![] };
    v["Answer"].as_array().map(|a| a.iter().filter_map(|x| x["data"].as_str()).map(|s| s.replace('"', "")).collect()).unwrap_or_default()
}

fn score(f: &[Finding], cat: &str) -> u32 {
    let (mut g, mut t) = (0.0, 0.0);
    for x in f.iter().filter(|x| x.cat == cat) {
        let w = match x.sev { "high" => 3.0, "med" => 2.0, _ => 1.0 };
        t += w; g += match x.status { "pass" => w, "warn" => w * 0.5, _ => 0.0 };
    }
    if t == 0.0 { 100 } else { (g / t * 100.0_f64).round() as u32 }
}

// depth: 1 = yalnızca ana sayfa, N = en fazla N sayfa, 0 = bulunabilen tüm sayfalar (SITE_MAX tavanıyla).
pub async fn run(input: String, depth: usize, cancel: Arc<AtomicBool>, prog: &(dyn Fn(String) + Send + Sync)) -> Result<Report, String> {
    let mut u = input.trim().to_string();
    if !u.contains("://") { u = format!("https://{u}"); }
    let parsed = Url::parse(&u).map_err(|_| "Geçersiz adres. Örnek: ornek.com".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() { return Err("Yalnızca http ve https desteklenir.".into()); }
    let limit = if depth == 0 { SITE_MAX } else { depth.clamp(1, SITE_MAX) };
    let c = Client::builder().user_agent(UA).timeout(Duration::from_secs(15)).tls_info(true).build().map_err(|e| e.to_string())?;

    prog("Siteye bağlanılıyor".into());
    let t = Instant::now();
    let r = c.get(parsed).send().await.map_err(|e| format!("Siteye ulaşılamadı: {e}"))?;
    let ms = t.elapsed().as_millis() as u64;
    let (status, fin, h) = (r.status().as_u16(), r.url().clone(), r.headers().clone());
    let tls = r.extensions().get::<reqwest::tls::TlsInfo>().and_then(|i| i.peer_certificate()).and_then(Cert::parse);
    let body = r.text().await.unwrap_or_default();
    let mut f: Vec<Finding> = Vec::new();
    let https = fin.scheme() == "https";

    prog("TLS sertifikası ve güvenlik başlıkları inceleniyor".into());
    if let Some(t) = &tls {
        add(&mut f, "sec", "high", if t.days_left < 14 { Some(false) } else if t.days_left < 30 { None } else { Some(true) }, "TLS sertifikası süresi", format!("Sertifikanın bitmesine {} gün var ({}).", t.days_left, t.expires), "CWE-298", &["Sertifikayı hemen yenileyin.", "Otomatik yenileme kurun (`certbot renew` zamanlaması veya barındırıcı ayarı)."]);
    }
    let cookies = header_checks(&h, https, &mut f);
    if https {
        if let Ok(nc) = Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(8)).user_agent(UA).build() {
            let mut hu = fin.clone(); let _ = hu.set_scheme("http"); let _ = hu.set_port(None);
            if let Ok(r) = nc.get(hu).send().await {
                let ok = r.status().is_redirection() && hv(r.headers(), "location").unwrap_or_default().starts_with("https://");
                add(&mut f, "sec", "med", Some(ok), "HTTP → HTTPS yönlendirmesi", "http:// adresi HTTPS’e yönlendirmiyor.", "CWE-319", &["Sunucuda 80. portu 301 ile HTTPS’e yönlendirin."]);
            }
        }
    }
    prog("HTML yapısı çözümleniyor".into());
    let ho = html_checks(&body, &fin, &h, &mut f);

    // --- Performans
    add(&mut f, "qual", "med", if ms < 800 { Some(true) } else if ms < 2000 { None } else { Some(false) }, "Sunucu yanıt süresi", format!("İlk yanıt {ms} ms."), "Core Web Vitals (TTFB)", &["Sunucu tarafı önbellekleme (CDN, sayfa önbelleği) ekleyin.", "Yavaş veritabanı sorgularını profil çıkararak bulun."]);
    add(&mut f, "qual", "low", if body.len() < 1_500_000 { Some(true) } else { None }, "HTML boyutu", format!("{} KB HTML.", body.len() / 1024), "Sayfa ağırlığı", &["Satır içi büyük veriyi dış dosyaya taşıyın.", "Gereksiz DOM öğelerini azaltın."]);
    if let Ok(r) = c.head(fin.clone()).header("accept-encoding", "gzip, br").send().await {
        add(&mut f, "qual", "med", Some(hv(r.headers(), "content-encoding").is_some() || body.len() < 8000), "Sıkıştırma (gzip/brotli)", "Yanıt sıkıştırılmadan gönderiliyor.", "Sayfa hızı", &["nginx: `gzip on;` ve `gzip_types text/css application/javascript;` ekleyin.", "Mümkünse brotli etkinleştirin."]);
    }
    add(&mut f, "qual", "low", Some(hv(&h, "cache-control").is_some()), "Önbellek başlığı", "`Cache-Control` yok.", "Sayfa hızı", &["Statik dosyalar için `Cache-Control: public, max-age=31536000, immutable` ekleyin."]);

    // --- robots.txt ve YZ botları
    prog("robots.txt, llms.txt, sitemap ve security.txt bakılıyor".into());
    let robots = fetch(&c, &fin, "/robots.txt").await;
    add(&mut f, "ai", "med", Some(robots.is_some()), "robots.txt", "Dosya bulunamadı.", "Robots Exclusion", &["Kök dizine `robots.txt` ekleyin ve `Sitemap:` satırını yazın."]);
    let (blocked, star) = robots.as_deref().map(robots_groups).unwrap_or_default();
    let bots: Vec<(String, bool)> = BOTS.iter().map(|b| (b.to_string(), !blocked.contains(b))).collect();
    if robots.is_some() {
        add(&mut f, "ai", "med", if blocked.is_empty() { Some(true) } else { None }, "Yapay zekâ botlarına erişim", format!("Engellenen botlar: {}", blocked.join(", ")), "Robots Exclusion", &["Yapay zekâ araçlarında görünmek istiyorsanız ilgili `Disallow: /` satırlarını kaldırın.", "Bilinçli bir tercihse bu bir hata değildir."]);
    }
    add(&mut f, "ai", "low", Some(fetch(&c, &fin, "/llms.txt").await.is_some()), "llms.txt", "Yapay zekâ için site özeti dosyası yok.", "llmstxt.org", &["Kök dizine Markdown biçiminde `llms.txt` ekleyin: başlık, kısa özet, önemli sayfa bağlantıları."]);
    let sm_urls: Vec<Url> = if limit > 1 { prog("Site haritası okunuyor".into()); sitemap_urls(&c, &fin, robots.as_deref()).await } else { vec![] };
    let sm = robots.as_deref().map_or(false, |r| r.to_lowercase().contains("sitemap:")) || !sm_urls.is_empty()
        || (limit == 1 && match fin.join("/sitemap.xml").ok() { Some(u) => get_body(&c, &u).await.map_or(false, |x| x.contains("<urlset") || x.contains("<sitemapindex")), None => false });
    add(&mut f, "ai", "med", Some(sm), "Site haritası", "sitemap.xml bulunamadı.", "Sitemaps", &["Sitenizin sayfalarını listeleyen `sitemap.xml` üretin."]);
    let sec = fetch(&c, &fin, "/.well-known/security.txt").await.map_or(false, |t| t.to_lowercase().contains("contact:"));
    add(&mut f, "sec", "low", Some(sec), "security.txt", "Güvenlik açığı bildirimi için iletişim dosyası yok.", "RFC 9116", &["`/.well-known/security.txt` oluşturup `Contact: mailto:guvenlik@alanadiniz.com` ve `Expires:` satırlarını ekleyin."]);

    // --- Çok sayfalı tarama (robots.txt'e uyar, istekler arası bekler)
    let mut pages: Vec<PageInfo> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut q: VecDeque<Url> = VecDeque::new();
    let mut anchors_all: Vec<(String, Url)> = vec![];
    let mut corpus = clip(&body.to_lowercase(), 400_000);
    seen.insert(key(&fin));
    let f0 = facts(&body, &fin);
    let push_page = |pages: &mut Vec<PageInfo>, url: &Url, st: u16, ms: u64, bytes: usize, fx: Option<&Facts>| {
        let mut issues = vec![];
        if st >= 400 || st == 0 { issues.push(if st == 0 { "Ulaşılamadı".to_string() } else { format!("HTTP {st}") }); }
        if let Some(x) = fx { if x.title.is_empty() { issues.push("Başlık yok".into()); } if !x.desc { issues.push("Meta açıklama yok".into()); } if x.h1 == 0 { issues.push("h1 yok".into()); } if x.words < 80 { issues.push("Az metin".into()); } }
        pages.push(PageInfo { url: url.to_string(), status: st, ms, bytes, title: fx.map(|x| x.title.clone()).unwrap_or_default(), words: fx.map_or(0, |x| x.words), issues });
    };
    push_page(&mut pages, &fin, status, ms, body.len(), Some(&f0));
    let enqueue = |fx: &Facts, q: &mut VecDeque<Url>, seen: &mut HashSet<String>| {
        for (_, a) in &fx.anchors { if a.host_str() == fin.host_str() && crawlable(a) && seen.len() < SEEN_MAX && seen.insert(key(a)) { q.push_back(a.clone()); } }
    };
    enqueue(&f0, &mut q, &mut seen);
    anchors_all.extend(f0.anchors.iter().cloned());
    // Site haritasındaki sayfalar da kuyruğa girer (ana sayfadan bağlantısı olmayan sayfaları yakalar)
    for a in &sm_urls { if a.host_str() == fin.host_str() && crawlable(a) && seen.len() < SEEN_MAX && seen.insert(key(a)) { q.push_back(a.clone()); } }
    let mut was_cancelled = false;
    while pages.len() < limit {
        if cancel.load(Ordering::Relaxed) { was_cancelled = true; prog("Tarama durduruldu; o ana kadarki sonuçlar raporlanıyor".into()); break; }
        let Some(u) = q.pop_front() else { break };
        if star.iter().any(|r| u.path().starts_with(r.as_str())) { continue; }
        if depth == 0 { prog(format!("Sayfa {} taranıyor ({} sırada): {}", pages.len() + 1, q.len() + 1, u.path())); }
        else { prog(format!("Sayfa {}/{} taranıyor: {}", pages.len() + 1, limit, u.path())); }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let t0 = Instant::now();
        match c.get(u.clone()).send().await {
            Ok(r) => {
                let st = r.status().as_u16();
                let html = hv(r.headers(), "content-type").map_or(true, |c| c.contains("html"));
                let b = if html && st < 400 { r.text().await.unwrap_or_default() } else { String::new() };
                let ms = t0.elapsed().as_millis() as u64;
                if html {
                    let fx = if b.is_empty() { None } else { Some(facts(&b, &u)) };
                    push_page(&mut pages, &u, st, ms, b.len(), fx.as_ref());
                    if let Some(x) = &fx { enqueue(x, &mut q, &mut seen); anchors_all.extend(x.anchors.iter().cloned()); if corpus.len() < CORPUS_MAX { corpus.push_str(&clip(&b.to_lowercase(), 100_000)); } }
                }
            }
            Err(_) => push_page(&mut pages, &u, 0, 0, 0, None),
        }
    }
    let broken = pages.iter().filter(|p| p.status >= 400 || p.status == 0).count();
    add(&mut f, "qual", "med", Some(broken == 0), "Kırık sayfalar", format!("{} sayfa taramada hata verdi.", broken), "SEO · Kullanıcı deneyimi", &["Kırık bağlantıları düzeltin veya 301 ile doğru adrese yönlendirin.", "Sayfalar sekmesinde hangi adreslerin hata verdiğini görebilirsiniz."]);
    let mut tc: HashMap<&str, usize> = HashMap::new();
    for p in pages.iter().filter(|p| !p.title.is_empty()) { *tc.entry(p.title.as_str()).or_default() += 1; }
    let dup = tc.values().filter(|n| **n > 1).count();
    add(&mut f, "ai", "low", Some(dup == 0), "Yinelenen sayfa başlıkları", format!("{dup} başlık birden fazla sayfada tekrar ediyor."), "SEO", &["Her sayfaya o sayfaya özgü bir `<title>` yazın."]);
    let thin = pages.iter().filter(|p| p.status < 400 && (p.title.is_empty() || p.words < 80)).count();
    if pages.len() > 1 { add(&mut f, "ai", "med", if thin == 0 { Some(true) } else { None }, "Eksik başlıklı veya metinsiz sayfalar", format!("{thin} sayfada başlık yok veya metin çok az."), "SEO", &["Boş görünen sayfaları sunucu tarafında üretin ve başlık ekleyin."]); }

    // --- Mevzuat: bağlantıları bul, sayfa içeriklerini oku
    prog("Yasal sayfalar okunuyor".into());
    let pl = find_link(&anchors_all, &["gizlilik", "privacy", "kvkk", "aydınlatma", "aydinlatma"]);
    let cl = find_link(&anchors_all, &["çerez", "cerez", "cookie"]);
    let tl = find_link(&anchors_all, &["kullanım", "kullanim", "koşul", "kosul", "terms", "sözleşme"]);
    let dl = find_link(&anchors_all, &["mesafeli", "iade", "cayma", "refund"]);
    let ptxt = match &pl { Some(u) => get_body(&c, u).await.map(|b| text_low(&b)), None => None };
    let ctxt = match &cl { Some(u) => get_body(&c, u).await.map(|b| text_low(&b)), None => None };
    let dtxt = match &dl { Some(u) => get_body(&c, u).await.map(|b| text_low(&b)), None => None };
    let has = |ks: &[&str]| ks.iter().any(|k| corpus.contains(k));
    let pm = ptxt.as_deref().map(|t| missing(t, &[("veri sorumlusu", &["veri sorumlusu", "data controller"]), ("işleme amaçları", &["amaç", "purpose"]), ("aktarım bilgisi", &["aktar", "paylaş", "transfer"]), ("saklama süresi", &["saklan", "süre", "retention"]), ("ilgili kişi hakları", &["haklar", "rights"]), ("başvuru yolu", &["başvuru", "iletişim", "contact"])]));
    match (&pl, &pm) {
        (None, _) => add(&mut f, "legal", "high", Some(false), "Gizlilik / KVKK aydınlatma metni", "Tarama boyunca böyle bir sayfa bağlantısı bulunamadı.", "KVKK m.10 · GDPR m.13", &["6698 sayılı KVKK m.10 uyarınca Aydınlatma Metni hazırlayın: veri sorumlusu, işleme amacı, aktarım, saklama süresi, haklarınız.", "Footer’a her sayfadan erişilen bir bağlantı koyun."]),
        (Some(u), Some(m)) => add(&mut f, "legal", "high", if m.is_empty() { Some(true) } else if m.len() <= 2 { None } else { Some(false) }, "Gizlilik / KVKK aydınlatma metni içeriği", format!("{} bulundu. Metinde şunlar görünmüyor: {}", u.path(), m.join(", ")), "KVKK m.10 · GDPR m.13", &["Eksik başlıkları aydınlatma metnine ekleyin.", "Metni avukatınıza ya da KVKK danışmanınıza kontrol ettirin."]),
        (Some(u), None) => add(&mut f, "legal", "high", None, "Gizlilik sayfası okunamadı", format!("{} adresine ulaşılamadı.", u.path()), "KVKK m.10", &["Bağlantının doğru sayfaya gittiğini kontrol edin."]),
    }
    let cmp = CMPS.iter().any(|k| corpus.contains(k));
    let banner = has(&["kabul", "accept"]) && has(&["reddet", "reject", "decline", "tercih", "preferences"]);
    let tr = ho.trackers.join(", ");
    add(&mut f, "legal", "high", if ho.tracking { if cmp || banner { None } else { Some(false) } } else { Some(true) }, "İzleyiciler ve çerez rızası",
        if ho.tracking && !(cmp || banner) { format!("İlk yanıtta izleyiciler yüklü ({tr}) ama rıza mekanizması görünmüyor.") } else { format!("İzleyiciler: {tr}. Rıza mekanizması var; ancak bu araç, izleyicilerin onaydan önce çalışmadığını doğrulayamaz.") },
        "KVKK m.5/m.12 · ePrivacy", &["İzleyici betikleri rıza verilene kadar yüklemeyin (Google Tag Manager’da onay tetikleyicisi kullanın).", "Kabul ve Reddet seçeneklerini eşit görünürlükte sunun.", "Tarayıcı geliştirici araçlarında Ağ sekmesini açıp onay vermeden hangi isteklerin gittiğine bakın."]);
    add(&mut f, "legal", "med", if ho.thirds.is_empty() { Some(true) } else { None }, "Üçüncü taraf hizmetler", format!("Ziyaretçi IP adresi şu hizmetlere gidiyor: {}", ho.thirds.join(", ")), "KVKK m.9 · GDPR m.44", &["Google Fonts gibi kaynakları kendi sunucunuza alın.", "Aydınlatma metninde bu hizmetleri ve yurt dışı aktarımı belirtin."]);
    let cm = ctxt.as_deref().map(|t| missing(t, &[("çerez türleri", &["zorunlu", "analitik", "işlevsel", "pazarlama", "necessary", "analytics"]), ("saklama süresi", &["süre", "gün", "ay ", "duration"]), ("yönetim yolu", &["tarayıcı", "ayar", "reddet", "tercih", "settings"])]));
    add(&mut f, "legal", "med", match (&cl, &cm) { (None, _) => Some(false), (_, Some(m)) if m.is_empty() => Some(true), _ => None }, "Çerez politikası", match (&cl, &cm) { (None, _) => "Ayrı bir çerez politikası bulunamadı.".to_string(), (_, Some(m)) => format!("Bulundu. Eksik görünenler: {}", m.join(", ")), _ => "Sayfa okunamadı.".into() }, "KVKK · ePrivacy", &["Çerezleri türüne göre (zorunlu, analitik, pazarlama) listeleyin.", "Her çerezin süresini ve nasıl reddedileceğini yazın."]);
    add(&mut f, "legal", "med", Some(tl.is_some()), "Kullanım koşulları", "Koşullar sayfası bulunamadı.", "Genel hukuk", &["Hizmetin kapsamını ve sorumluluk sınırlarını anlatan bir Kullanım Koşulları sayfası ekleyin."]);
    add(&mut f, "legal", "med", Some(has(&["iletişim", "iletisim", "contact", "mailto:", "tel:"])), "İletişim ve ticari bilgiler", "Unvan/iletişim bilgisi bulunamadı.", "6563 sayılı Kanun · ETBİS", &["Unvan, adres, e-posta ve telefonu iletişim sayfasında yayımlayın."]);
    if has(&["sepet", "cart", "checkout"]) {
        let dm = dtxt.as_deref().map(|t| missing(t, &[("cayma hakkı", &["cayma", "withdrawal"]), ("14 günlük süre", &["14", "on dört"]), ("iade koşulları", &["iade", "refund"])]));
        add(&mut f, "legal", "high", match (&dl, &dm) { (None, _) => Some(false), (_, Some(m)) if m.is_empty() => Some(true), _ => None }, "Mesafeli satış ve iade", match (&dl, &dm) { (None, _) => "Alışveriş öğeleri var ama cayma/iade sayfası bulunamadı.".to_string(), (_, Some(m)) => format!("Sayfa var. Eksik görünenler: {}", m.join(", ")), _ => "Sayfa okunamadı.".into() }, "Mesafeli Sözleşmeler Yönetmeliği", &["Ön bilgilendirme formu, 14 gün cayma hakkı ve iade koşullarını yayımlayın."]);
    }

    // --- DNS (Cloudflare DoH üzerinden; yalnızca alan adı sorgulanır)
    prog("E-posta DNS kayıtları (SPF, DMARC) kontrol ediliyor".into());
    let mut dns: Vec<(String, String)> = vec![];
    let hs = fin.host_str().unwrap_or("");
    if hs.parse::<std::net::IpAddr>().is_err() {
        let apex = hs.strip_prefix("www.").unwrap_or(hs);
        let mx = doh(&c, apex, "MX").await;
        if !mx.is_empty() {
            dns.push(("MX".into(), clip(&mx.join(" | "), 160)));
            let spf = doh(&c, apex, "TXT").await.into_iter().find(|t| t.starts_with("v=spf1"));
            let dmarc = doh(&c, &format!("_dmarc.{apex}"), "TXT").await.into_iter().find(|t| t.starts_with("v=DMARC1"));
            dns.push(("SPF".into(), spf.clone().unwrap_or("yok".into())));
            dns.push(("DMARC".into(), dmarc.clone().unwrap_or("yok".into())));
            add(&mut f, "sec", "med", Some(spf.is_some()), "SPF kaydı", "Alan adı adına sahte e-posta gönderilmesini zorlaştıran SPF kaydı yok.", "E-posta sahteciliği", &["DNS’e TXT kaydı ekleyin: `v=spf1 include:<posta-saglayicisi> ~all`."]);
            add(&mut f, "sec", "med", match &dmarc { None => Some(false), Some(d) if d.contains("p=none") => None, _ => Some(true) }, "DMARC kaydı", "DMARC yok veya `p=none` (yalnızca izleme).", "E-posta sahteciliği", &["`_dmarc` altında TXT ekleyin: `v=DMARC1; p=quarantine; rua=mailto:dmarc@alanadiniz.com`.", "Raporları inceleyip `p=reject`’e geçin."]);
        }
    }

    prog("Rapor hazırlanıyor".into());
    let sc = [score(&f, "sec"), score(&f, "legal"), score(&f, "ai"), score(&f, "qual")];
    let total = (sc[0] * 40 + sc[1] * 25 + sc[2] * 20 + sc[3] * 15) / 100;
    let mut headers: Vec<(String, String)> = h.iter().filter(|(k, _)| k.as_str() != "set-cookie").take(40).map(|(k, v)| (k.to_string(), clip(v.to_str().unwrap_or("?"), 200))).collect();
    headers.sort();
    let left = q.iter().filter(|u| !star.iter().any(|r| u.path().starts_with(r.as_str()))).count();
    if left > 0 && !was_cancelled { prog(format!("{left} sayfa tarama sınırı nedeniyle taranmadı")); }
    Ok(Report { url: fin.to_string(), status, ms, bytes: body.len(), scores: sc, total, findings: f, pages, ai_view: ho.ai, bots, headers, cookies, tech: ho.tech, trackers: ho.trackers, tls, dns, left, cancelled: was_cancelled })
}
