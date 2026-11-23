//! مركز الأدوات (Marketplace) — المرحلة 8.
//!
//! الخلفية: مستودع GitHub عام يحوي فهرساً ثابتاً `index.json` وحزم `.tarpkg`.
//! لا خادم ولا حسابات جديدة. كل ما يلي يُفرض هنا في Rust لا في الواجهة:
//!
//! - الفهرس موقَّع من «مفتاح المراجِع» (Ed25519) المثبَّت يدوياً عند ضبط المتجر؛ فهرس غير موقَّع أو معدَّل يُرفض.
//! - رقم تسلسلي `seq` متزايد: يُرفض أي فهرس أقدم من آخر ما رُئي (حماية من إعادة فهرس قديم يُخفي الإلغاءات).
//! - الحزمة تُنزَّل من مسار يُبنى من (id, version) المتحقَّق منهما، لا من رابط يرسله الفهرس.
//! - لا تُثبَّت إلا حزمة حالتها «معتمدة»، مطابقة لـ sha256، موقَّعة بمفتاح المراجِع نفسه،
//!   وصلاحياتها في manifest مطابقة لما في الفهرس.
//! - الإيقاف/الإلغاء بعد النشر: الأداة المثبّتة بإصدار موقوف أو ملغى تُعطَّل تلقائياً عند تحديث الفهرس.
//! - إدراج أداة في المتجر لا يمنح أي صلاحية: الموافقة على الصلاحيات تبقى منفصلة وللمشرف.
//!
//! المراجعة ليست ضماناً مطلقاً للأمان.

use crate::plugin::{self, InstallOutcome, KNOWN_PERMISSIONS};
use crate::security::{self, key_id_of, SIG_PATH};
use crate::storage::Db;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::path::Path;

pub const MAX_INDEX_BYTES: usize = 1024 * 1024;
pub const MAX_PACKAGE_BYTES: usize = 20 * 1024 * 1024;
const MAX_ENTRIES: usize = 500;
const BRANCH: &str = "main";
/// بادئة النطاق: تمنع استخدام توقيع الفهرس كتوقيع حزمة أو العكس.
pub const INDEX_MAGIC: &[u8] = b"TARPKG-INDEX-V1\n";

const K_REPO: &str = "market.repo";
const K_KEY: &str = "market.key";
const K_SEQ: &str = "market.seq";

pub const STATUSES: [&str; 7] = [
    "draft",
    "scanning",
    "review",
    "rejected",
    "approved",
    "suspended",
    "revoked",
];

// ---------------------------------------------------------------------------
// جلب الشبكة (قابل للاستبدال في الاختبارات)
// ---------------------------------------------------------------------------

pub trait Fetcher {
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>, String>;
}

/// جلب HTTPS فعلي. لا يتبع التحويلات ولا يقبل إلا استجابة 200.
pub struct HttpFetcher;

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>, String> {
        if !url.starts_with("https://raw.githubusercontent.com/") {
            return Err("مصدر غير مسموح: يُسمح فقط بـ raw.githubusercontent.com".into());
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .redirects(0)
            .user_agent("TerminalAR-Marketplace")
            .build();
        let resp = agent.get(url).call().map_err(|e| match e {
            ureq::Error::Status(code, _) => {
                format!("رد الخادم برمز {code} (تحقق من اسم المستودع وأن الملف موجود)")
            }
            other => format!("تعذّر الاتصال بالمتجر: {other}"),
        })?;
        if resp.status() != 200 {
            return Err(format!("رد غير متوقع من الخادم: {}", resp.status()));
        }
        let mut buf = Vec::new();
        resp.into_reader()
            .take(max as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("انقطع التنزيل: {e}"))?;
        if buf.len() > max {
            return Err("الملف أكبر من الحد المسموح".into());
        }
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// الإعداد
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub repo: String,
    pub key: String,
    pub key_id: String,
}

fn repo_part_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 100
        && !p.starts_with('.')
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub fn valid_repo(s: &str) -> bool {
    let mut it = s.split('/');
    match (it.next(), it.next(), it.next()) {
        (Some(o), Some(n), None) => repo_part_ok(o) && repo_part_ok(n),
        _ => false,
    }
}

fn parse_key(b64: &str) -> Result<([u8; 32], VerifyingKey), String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|_| "المفتاح العام ليس بصيغة base64 صالحة".to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "المفتاح العام يجب أن يكون 32 بايتاً (Ed25519)".to_string())?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| "المفتاح العام غير صالح".to_string())?;
    Ok((arr, vk))
}

pub fn config_get(db: &Db) -> Result<Option<Config>, String> {
    let repo = db.setting_get(K_REPO)?.unwrap_or_default();
    let key = db.setting_get(K_KEY)?.unwrap_or_default();
    if repo.is_empty() || key.is_empty() {
        return Ok(None);
    }
    let (arr, _) = parse_key(&key)?;
    Ok(Some(Config {
        repo,
        key,
        key_id: key_id_of(&arr),
    }))
}

/// يضبط المستودع ومفتاح المراجِع. المفتاح يُضاف إلى الناشرين الموثوقين (للعرض فقط؛ لا يمنح صلاحيات).
pub fn config_set(db: &Db, repo: &str, key_b64: &str) -> Result<Config, String> {
    let repo = repo.trim();
    if !valid_repo(repo) {
        return Err("اسم المستودع يجب أن يكون بالشكل owner/name (حروف وأرقام و - _ . فقط)".into());
    }
    let (arr, _) = parse_key(key_b64)?;
    let new_id = key_id_of(&arr);
    if let Some(old) = config_get(db)? {
        if old.key_id != new_id {
            let _ = security::trust_remove(db, &old.key_id);
        }
    }
    security::trust_add(db, "مراجِع المتجر", key_b64.trim())?;
    db.setting_set(K_REPO, repo)?;
    db.setting_set(K_KEY, key_b64.trim())?;
    db.setting_set(K_SEQ, "0")?;
    let _ = db.audit_add("market_config", repo, &new_id);
    Ok(Config {
        repo: repo.to_string(),
        key: key_b64.trim().to_string(),
        key_id: new_id,
    })
}

pub fn config_clear(db: &Db) -> Result<(), String> {
    if let Some(old) = config_get(db)? {
        let _ = security::trust_remove(db, &old.key_id);
    }
    db.setting_set(K_REPO, "")?;
    db.setting_set(K_KEY, "")?;
    db.setting_set(K_SEQ, "0")?;
    let _ = db.audit_add("market_config", "", "cleared");
    Ok(())
}

fn raw_url(repo: &str, path: &str) -> String {
    format!("https://raw.githubusercontent.com/{repo}/{BRANCH}/{path}")
}

// ---------------------------------------------------------------------------
// الفهرس
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rating {
    pub avg: f32,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub developer: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub size: u64,
    pub sha256: String,
    pub status: String,
    #[serde(default)]
    pub reviewed_at: Option<String>,
    /// سبب الإيقاف/الإلغاء أو ملاحظة المراجعة.
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub rating: Option<Rating>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Index {
    pub schema: u32,
    pub seq: u64,
    pub updated: String,
    #[serde(default)]
    pub name: String,
    pub packages: Vec<Entry>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn validate_index(ix: &Index) -> Result<(), String> {
    if ix.schema != 1 {
        return Err(format!("إصدار صيغة الفهرس غير مدعوم: {}", ix.schema));
    }
    if ix.packages.len() > MAX_ENTRIES {
        return Err(format!("الفهرس يحوي أكثر من {MAX_ENTRIES} إدخال"));
    }
    let mut seen = BTreeSet::new();
    for e in &ix.packages {
        let at = format!("{}@{}", e.id, e.version);
        if !plugin::is_slug(&e.id, 32) {
            return Err(format!("معرّف غير صالح في الفهرس: {}", e.id));
        }
        if Version::parse(&e.version).is_err() {
            return Err(format!("إصدار غير صالح في الفهرس: {at}"));
        }
        if !is_hex64(&e.sha256) {
            return Err(format!("sha256 غير صالح في الفهرس: {at}"));
        }
        if !STATUSES.contains(&e.status.as_str()) {
            return Err(format!("حالة غير معروفة في الفهرس: {at} ({})", e.status));
        }
        if e.size == 0 || e.size as usize > MAX_PACKAGE_BYTES {
            return Err(format!("حجم غير مقبول في الفهرس: {at}"));
        }
        if e.name.chars().count() > 80
            || e.developer.chars().count() > 80
            || e.description.chars().count() > 600
            || e.notes.as_deref().map(|n| n.chars().count()).unwrap_or(0) > 600
        {
            return Err(format!("نص أطول من المسموح في الفهرس: {at}"));
        }
        if let Some(p) = e
            .permissions
            .iter()
            .find(|p| !KNOWN_PERMISSIONS.contains(&p.as_str()))
        {
            return Err(format!("صلاحية غير معروفة في الفهرس: {at} ({p})"));
        }
        if let Some(r) = &e.rating {
            if !(0.0..=5.0).contains(&r.avg) {
                return Err(format!("تقييم خارج المدى في الفهرس: {at}"));
            }
        }
        if !seen.insert((e.id.clone(), e.version.clone())) {
            return Err(format!("إدخال مكرر في الفهرس: {at}"));
        }
    }
    Ok(())
}

/// يتحقق من توقيع الفهرس (الحمولة = INDEX_MAGIC + البايتات الخام لـ index.json).
pub fn verify_index_sig(index_bytes: &[u8], sig_b64: &[u8], key_b64: &str) -> Result<(), String> {
    let (_, vk) = parse_key(key_b64)?;
    let text = std::str::from_utf8(sig_b64).map_err(|_| "ملف توقيع الفهرس غير صالح".to_string())?;
    let sig_bytes = B64
        .decode(text.trim())
        .map_err(|_| "ملف توقيع الفهرس غير صالح".to_string())?;
    let arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "طول توقيع الفهرس غير صحيح".to_string())?;
    let mut payload = INDEX_MAGIC.to_vec();
    payload.extend_from_slice(index_bytes);
    vk.verify(&payload, &Signature::from_bytes(&arr))
        .map_err(|_| "توقيع الفهرس لا يطابق مفتاح المراجِع — الفهرس معدَّل أو من جهة أخرى".to_string())
}

fn need_config(db: &Db) -> Result<Config, String> {
    config_get(db)?
        .ok_or_else(|| "لم يُضبط مصدر المتجر بعد (المشرف يضبط المستودع ومفتاح المراجِع)".to_string())
}

/// يجلب الفهرس ويتحقق منه ويطبّق حماية التراجع. لا يعدّل شيئاً سوى آخر seq.
pub fn fetch_index(db: &Db, f: &dyn Fetcher) -> Result<Index, String> {
    let cfg = need_config(db)?;
    let body = f.get(&raw_url(&cfg.repo, "index.json"), MAX_INDEX_BYTES)?;
    let sig = f.get(&raw_url(&cfg.repo, "index.sig"), 4096)?;
    verify_index_sig(&body, &sig, &cfg.key).inspect_err(|e| {
        let _ = db.audit_add("market_index_rejected", &cfg.repo, e);
    })?;
    let ix: Index = serde_json::from_slice(&body).map_err(|e| format!("الفهرس غير صالح: {e}"))?;
    validate_index(&ix)?;
    let last: u64 = db
        .setting_get(K_SEQ)?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if ix.seq < last {
        let _ = db.audit_add("market_index_rejected", &cfg.repo, "rollback");
        return Err(format!(
            "الفهرس أقدم من آخر فهرس رُئي (seq {} < {last}) — قد يكون نسخة قديمة تُخفي إلغاءات؛ رُفض",
            ix.seq
        ));
    }
    db.setting_set(K_SEQ, &ix.seq.to_string())?;
    Ok(ix)
}

// ---------------------------------------------------------------------------
// الإيقاف والإلغاء بعد النشر
// ---------------------------------------------------------------------------

/// يعطّل الأدوات المثبّتة بإصدار موقوف أو ملغى في الفهرس. يعيد وصفاً لما عُطّل.
pub fn apply_revocations(db: &Db, ix: &Index) -> Vec<String> {
    let mut out = Vec::new();
    for e in &ix.packages {
        if e.status != "suspended" && e.status != "revoked" {
            continue;
        }
        let Ok(Some(row)) = db.tool_get(&e.id) else {
            continue;
        };
        if row.source == "builtin" || row.version != e.version || !row.enabled {
            continue;
        }
        if plugin::set_enabled(db, &e.id, false).is_ok() {
            let why = e.notes.clone().unwrap_or_default();
            let _ = db.audit_add(
                "market_disable",
                &e.id,
                &format!("{} {} — {}", e.status, e.version, why),
            );
            out.push(format!(
                "عُطّلت «{}» {} لأن الإصدار {} في المتجر: {}",
                e.name,
                e.version,
                if e.status == "revoked" {
                    "ملغى"
                } else {
                    "موقوف"
                },
                if why.is_empty() {
                    "بلا سبب مذكور".to_string()
                } else {
                    why
                }
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// العرض
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    #[serde(flatten)]
    pub entry: Entry,
    pub installed_version: Option<String>,
    /// الأداة المثبّتة هي نفسها الحزمة المعتمدة من المتجر (مطابقة sha256) لا استيراداً محلياً.
    pub official: bool,
    /// install | update | installed | blocked | pending
    pub state: String,
    pub blocked_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarketView {
    pub repo: String,
    pub key_id: String,
    pub name: String,
    pub updated: String,
    pub seq: u64,
    pub items: Vec<Item>,
    /// رسائل عن أدوات عُطّلت بسبب إيقاف/إلغاء.
    pub disabled: Vec<String>,
}

fn ver(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|_| Version::new(0, 0, 0))
}

pub fn build_items(db: &Db, ix: &Index) -> Result<Vec<Item>, String> {
    let mut ids: Vec<&str> = ix.packages.iter().map(|e| e.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    let mut items = Vec::new();
    for id in ids {
        let all: Vec<&Entry> = ix.packages.iter().filter(|e| e.id == id).collect();
        let best_ok = all
            .iter()
            .filter(|e| e.status == "approved")
            .max_by_key(|e| ver(&e.version));
        let top = all.iter().max_by_key(|e| ver(&e.version));
        let Some(shown) = best_ok.or(top) else {
            continue;
        };
        // الأعمال قيد التحضير (مسودة/فحص/مراجعة/مرفوضة) تُعرض فقط إن لم يوجد إصدار معتمد أو محجوب.
        let blocked_versions: Vec<String> = all
            .iter()
            .filter(|e| e.status == "suspended" || e.status == "revoked")
            .map(|e| e.version.clone())
            .collect();
        let row = db.tool_get(id)?;
        let installed_version = row.as_ref().map(|r| r.version.clone());
        let official = row
            .as_ref()
            .map(|r| {
                r.source != "builtin"
                    && all.iter().any(|e| {
                        e.version == r.version && Some(&e.sha256) == r.package_sha256.as_ref()
                    })
            })
            .unwrap_or(false);
        let state = if shown.status != "approved" {
            if shown.status == "suspended" || shown.status == "revoked" {
                "blocked"
            } else {
                "pending"
            }
        } else {
            match &installed_version {
                None => "install",
                Some(v) if ver(v) < ver(&shown.version) => "update",
                Some(_) => "installed",
            }
        };
        items.push(Item {
            entry: (*shown).clone(),
            installed_version,
            official,
            state: state.to_string(),
            blocked_versions,
        });
    }
    Ok(items)
}

pub fn refresh(db: &Db, f: &dyn Fetcher) -> Result<MarketView, String> {
    let cfg = need_config(db)?;
    let ix = fetch_index(db, f)?;
    let disabled = apply_revocations(db, &ix);
    let items = build_items(db, &ix)?;
    Ok(MarketView {
        repo: cfg.repo,
        key_id: cfg.key_id,
        name: ix.name,
        updated: ix.updated,
        seq: ix.seq,
        items,
        disabled,
    })
}

// ---------------------------------------------------------------------------
// التثبيت
// ---------------------------------------------------------------------------

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    format!("{:x}", h.finalize())
}

/// فحوص الحزمة المنزّلة مقابل إدخال الفهرس (قبل أن يراها محرك الأدوات).
pub fn check_download(bytes: &[u8], e: &Entry, cfg: &Config) -> Result<(), String> {
    if bytes.len() as u64 != e.size {
        return Err("حجم الحزمة المنزّلة لا يطابق الفهرس".into());
    }
    if sha256_hex(bytes) != e.sha256 {
        return Err("بصمة sha256 للحزمة لا تطابق الفهرس — الحزمة تالفة أو مبدَّلة".into());
    }
    let mut ar = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| "الملف المنزّل ليس حزمة .tarpkg صالحة".to_string())?;
    let raw = {
        let mut mf = ar
            .by_name("manifest.json")
            .map_err(|_| "الحزمة لا تحتوي manifest.json".to_string())?;
        let mut buf = Vec::new();
        (&mut mf)
            .take(256 * 1024 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        if buf.len() > 256 * 1024 {
            return Err("manifest.json أكبر من 256KB".into());
        }
        buf
    };
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("manifest.json غير صالح: {e}"))?;
    let m_id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
    let m_ver = v.get("version").and_then(|x| x.as_str()).unwrap_or("");
    if m_id != e.id || m_ver != e.version {
        return Err("هوية الحزمة (id/version) لا تطابق إدخال الفهرس".into());
    }
    let m_perms: BTreeSet<String> = v
        .get("permissions")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let ix_perms: BTreeSet<String> = e.permissions.iter().cloned().collect();
    if m_perms != ix_perms {
        return Err("الصلاحيات المعلنة في الحزمة لا تطابق ما في الفهرس".into());
    }
    let sig = security::verify_package(&mut ar)?;
    if sig.kind != "signed" {
        return Err("الحزمة غير موقَّعة — المتجر لا يثبّت إلا حزماً موقّعة من المراجِع".into());
    }
    if sig.key_id.as_deref() != Some(cfg.key_id.as_str()) {
        return Err("الحزمة موقَّعة بمفتاح غير مفتاح المراجِع — لم تمرّ بمراجعة المتجر".into());
    }
    Ok(())
}

pub fn install(
    db: &Db,
    tools_dir: &Path,
    f: &dyn Fetcher,
    id: &str,
    version: &str,
    app_version: &str,
) -> Result<InstallOutcome, String> {
    if !plugin::is_slug(id, 32) || Version::parse(version).is_err() {
        return Err("معرّف أو إصدار غير صالح".into());
    }
    let cfg = need_config(db)?;
    let ix = fetch_index(db, f)?;
    // الإيقاف/الإلغاء يُطبَّق حتى لو كان المستخدم يثبّت شيئاً آخر.
    let _ = apply_revocations(db, &ix);
    let e = ix
        .packages
        .iter()
        .find(|e| e.id == id && e.version == version)
        .ok_or_else(|| "الإصدار غير موجود في الفهرس".to_string())?;
    if e.status != "approved" {
        return Err(format!(
            "لا يمكن تثبيت هذا الإصدار: حالته «{}»{}",
            status_ar(&e.status),
            e.notes
                .as_deref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default()
        ));
    }
    let url = raw_url(
        &cfg.repo,
        &format!("packages/{}-{}.tarpkg", e.id, e.version),
    );
    let bytes = f.get(&url, MAX_PACKAGE_BYTES)?;
    check_download(&bytes, e, &cfg).inspect_err(|err| {
        let _ = db.audit_add("market_install_rejected", id, err);
    })?;
    let out = plugin::install_package(db, tools_dir, &bytes, app_version)?;
    let _ = db.setting_set(&format!("market.sha.{id}"), &e.sha256);
    let _ = db.audit_add("market_install", id, version);
    Ok(out)
}

/// معرّفات الأدوات المثبّتة من المتجر (بصمة الحزمة المثبّتة تطابق ما سُجّل عند التثبيت منه)،
/// لتمييزها عن الحزم المحلية المستوردة للتجربة.
pub fn official_ids(db: &Db) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for t in plugin::list(db)? {
        if t.source == "builtin" {
            continue;
        }
        let Some(row) = db.tool_get(&t.id)? else {
            continue;
        };
        let rec = db.setting_get(&format!("market.sha.{}", t.id))?;
        if let (Some(r), Some(sha)) = (rec, row.package_sha256) {
            if !r.is_empty() && r == sha {
                out.push(t.id);
            }
        }
    }
    Ok(out)
}

pub fn status_ar(s: &str) -> &'static str {
    match s {
        "draft" => "مسودة",
        "scanning" => "قيد الفحص",
        "review" => "قيد المراجعة",
        "rejected" => "مرفوضة",
        "approved" => "معتمدة",
        "suspended" => "موقوفة",
        "revoked" => "ملغاة",
        _ => "غير معروفة",
    }
}

// ---------------------------------------------------------------------------
// تقييم وإبلاغ عبر GitHub Issues (الرابط يُفتح/يُنسخ يدوياً؛ لا يُرسل التطبيق شيئاً)
// ---------------------------------------------------------------------------

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// kind: "report" | "rating"
pub fn issue_url(db: &Db, kind: &str, id: &str, version: &str) -> Result<String, String> {
    let cfg = need_config(db)?;
    if !plugin::is_slug(id, 32) || Version::parse(version).is_err() {
        return Err("معرّف أو إصدار غير صالح".into());
    }
    let (title, body, label) = match kind {
        "report" => (
            format!("بلاغ: {id} {version}"),
            "نوع المشكلة (ضار / خادع / معطّل / آخر):\n\nالوصف:\n\nخطوات إعادة الحدوث:\n".to_string(),
            "report",
        ),
        "rating" => (
            format!("تقييم: {id} {version}"),
            "التقييم (1-5):\n\nتعليق:\n".to_string(),
            "rating",
        ),
        _ => return Err("نوع غير معروف".into()),
    };
    Ok(format!(
        "https://github.com/{}/issues/new?labels={}&title={}&body={}",
        cfg.repo,
        label,
        pct(&title),
        pct(&body)
    ))
}

// ---------------------------------------------------------------------------
// الاختبارات
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const APP: &str = "0.9.0";
    const REPO: &str = "me/tar-market";

    struct Mock(HashMap<String, Vec<u8>>);
    impl Fetcher for Mock {
        fn get(&self, url: &str, max: usize) -> Result<Vec<u8>, String> {
            let b = self.0.get(url).ok_or_else(|| format!("404 {url}"))?;
            if b.len() > max {
                return Err("كبير".into());
            }
            Ok(b.clone())
        }
    }

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "tarmkt-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn pub_b64(sk: &SigningKey) -> String {
        B64.encode(sk.verifying_key().to_bytes())
    }

    fn make_zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        for (n, d) in files {
            w.start_file(*n, opt).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn manifest(id: &str, version: &str) -> serde_json::Value {
        json!({
            "id": id, "name": "أداة", "developer": "Dev", "version": version,
            "description": "وصف", "platforms": ["windows", "linux", "macos"],
            "kind": "command", "engine": "shell", "permissions": ["process.run"],
            "actions": [{ "id": "go", "title": "تشغيل", "shell": "any", "steps": ["echo hi"] }]
        })
    }

    fn signed_pkg(m: &serde_json::Value, sk: &SigningKey) -> Vec<u8> {
        let files = vec![("manifest.json", m.to_string().into_bytes())];
        let base = make_zip(&files);
        let mut ar = zip::ZipArchive::new(Cursor::new(&base[..])).unwrap();
        let payload = security::signing_payload(&mut ar).unwrap();
        let sf = json!({
            "version": 1, "algorithm": "ed25519",
            "publicKey": pub_b64(sk),
            "signature": B64.encode(sk.sign(&payload).to_bytes()),
            "signer": "reviewer"
        });
        let mut all = files;
        all.push((SIG_PATH, sf.to_string().into_bytes()));
        make_zip(&all)
    }

    fn entry_for(pkg: &[u8], id: &str, version: &str, status: &str) -> serde_json::Value {
        json!({
            "id": id, "name": "أداة", "developer": "Dev", "version": version,
            "description": "وصف", "platforms": ["windows"], "permissions": ["process.run"],
            "size": pkg.len(), "sha256": sha256_hex(pkg), "status": status
        })
    }

    fn index_bytes(seq: u64, entries: Vec<serde_json::Value>) -> Vec<u8> {
        json!({ "schema": 1, "seq": seq, "updated": "2026-11-13", "name": "اختبار", "packages": entries })
            .to_string()
            .into_bytes()
    }

    fn sign_index(body: &[u8], sk: &SigningKey) -> Vec<u8> {
        let mut p = INDEX_MAGIC.to_vec();
        p.extend_from_slice(body);
        B64.encode(sk.sign(&p).to_bytes()).into_bytes()
    }

    fn url(p: &str) -> String {
        raw_url(REPO, p)
    }

    fn setup(reviewer: &SigningKey) -> Db {
        let db = Db::open_in_memory().unwrap();
        config_set(&db, REPO, &pub_b64(reviewer)).unwrap();
        db
    }

    fn mock_with(
        reviewer: &SigningKey,
        seq: u64,
        entries: Vec<serde_json::Value>,
        pkgs: Vec<(String, Vec<u8>)>,
    ) -> Mock {
        let body = index_bytes(seq, entries);
        let sig = sign_index(&body, reviewer);
        let mut m = HashMap::new();
        m.insert(url("index.json"), body);
        m.insert(url("index.sig"), sig);
        for (name, b) in pkgs {
            m.insert(url(&format!("packages/{name}")), b);
        }
        Mock(m)
    }

    #[test]
    fn repo_names_are_validated() {
        assert!(valid_repo("me/tar-market"));
        assert!(valid_repo("a.b/c_d"));
        for bad in [
            "", "me", "me/", "/x", "a/b/c", "../x", "a/..", "a b/c", "me/x?y", ".a/b", "a/.b",
        ] {
            assert!(!valid_repo(bad), "{bad}");
        }
    }

    #[test]
    fn index_signature_ok_tampered_and_wrong_key() {
        let rv = key(1);
        let body = index_bytes(1, vec![]);
        let sig = sign_index(&body, &rv);
        verify_index_sig(&body, &sig, &pub_b64(&rv)).unwrap();
        let mut t = body.clone();
        t.push(b' ');
        assert!(verify_index_sig(&t, &sig, &pub_b64(&rv)).is_err());
        assert!(verify_index_sig(&body, &sig, &pub_b64(&key(2))).is_err());
        assert!(verify_index_sig(&body, b"not base64!!", &pub_b64(&rv)).is_err());
    }

    #[test]
    fn index_signature_is_domain_separated_from_package_signature() {
        let rv = key(1);
        let body = index_bytes(1, vec![]);
        let raw_sig = B64.encode(rv.sign(&body).to_bytes());
        assert!(verify_index_sig(&body, raw_sig.as_bytes(), &pub_b64(&rv)).is_err());
    }

    #[test]
    fn validate_index_rejects_bad_entries() {
        let rv = key(1);
        let pkg = signed_pkg(&manifest("demo", "1.0.0"), &rv);
        let good = entry_for(&pkg, "demo", "1.0.0", "approved");
        let mk = |e: serde_json::Value| -> Result<(), String> {
            let ix: Index = serde_json::from_slice(&index_bytes(1, vec![e])).unwrap();
            validate_index(&ix)
        };
        mk(good.clone()).unwrap();
        let mut b = good.clone();
        b["sha256"] = json!("xyz");
        assert!(mk(b).is_err());
        let mut b = good.clone();
        b["permissions"] = json!(["root.everything"]);
        assert!(mk(b).is_err());
        let mut b = good.clone();
        b["status"] = json!("great");
        assert!(mk(b).is_err());
        let mut b = good.clone();
        b["id"] = json!("../evil");
        assert!(mk(b).is_err());
        let mut b = good.clone();
        b["version"] = json!("one");
        assert!(mk(b).is_err());
        let ix: Index = serde_json::from_slice(&index_bytes(1, vec![good.clone(), good])).unwrap();
        assert!(validate_index(&ix).is_err());
    }

    #[test]
    fn fetch_rejects_rollback_and_accepts_equal_or_newer() {
        let rv = key(1);
        let db = setup(&rv);
        fetch_index(&db, &mock_with(&rv, 5, vec![], vec![])).unwrap();
        fetch_index(&db, &mock_with(&rv, 5, vec![], vec![])).unwrap();
        fetch_index(&db, &mock_with(&rv, 6, vec![], vec![])).unwrap();
        let err = fetch_index(&db, &mock_with(&rv, 4, vec![], vec![])).unwrap_err();
        assert!(err.contains("أقدم"), "{err}");
    }

    #[test]
    fn fetch_rejects_index_signed_by_other_key() {
        let rv = key(1);
        let db = setup(&rv);
        let err = fetch_index(&db, &mock_with(&key(9), 1, vec![], vec![])).unwrap_err();
        assert!(err.contains("توقيع الفهرس"), "{err}");
    }

    #[test]
    fn unconfigured_market_is_refused() {
        let db = Db::open_in_memory().unwrap();
        let rv = key(1);
        assert!(fetch_index(&db, &mock_with(&rv, 1, vec![], vec![])).is_err());
        assert!(config_get(&db).unwrap().is_none());
    }

    #[test]
    fn install_happy_path_marks_official() {
        let rv = key(1);
        let db = setup(&rv);
        let pkg = signed_pkg(&manifest("demo", "1.0.0"), &rv);
        let m = mock_with(
            &rv,
            1,
            vec![entry_for(&pkg, "demo", "1.0.0", "approved")],
            vec![("demo-1.0.0.tarpkg".into(), pkg)],
        );
        let dir = tmp();
        let out = install(&db, &dir, &m, "demo", "1.0.0", APP).unwrap();
        assert_eq!(out.tool.id, "demo");
        let view = refresh(&db, &m).unwrap();
        let it = view.items.iter().find(|i| i.entry.id == "demo").unwrap();
        assert!(it.official);
        assert_eq!(it.state, "installed");
        assert_eq!(official_ids(&db).unwrap(), vec!["demo".to_string()]);
        // الناشر الموثوق (مفتاح المراجِع) سجّل كموثوق
        assert!(db
            .trusted_get(&key_id_of(&rv.verifying_key().to_bytes()))
            .unwrap()
            .is_some());
    }

    #[test]
    fn install_refuses_every_broken_variant() {
        let rv = key(1);
        let db = setup(&rv);
        let dir = tmp();
        let good = signed_pkg(&manifest("demo", "1.0.0"), &rv);

        // 1) sha256 مختلف عن الفهرس (حزمة مبدَّلة)
        let swapped = signed_pkg(&manifest("demo", "1.0.0"), &key(1));
        let mut e = entry_for(&good, "demo", "1.0.0", "approved");
        e["sha256"] = json!(sha256_hex(b"other"));
        let m = mock_with(&rv, 1, vec![e], vec![("demo-1.0.0.tarpkg".into(), swapped)]);
        assert!(install(&db, &dir, &m, "demo", "1.0.0", APP)
            .unwrap_err()
            .contains("sha256"));

        // 2) موقَّعة بمفتاح غير المراجِع
        let other = signed_pkg(&manifest("demo", "1.0.0"), &key(7));
        let m = mock_with(
            &rv,
            2,
            vec![entry_for(&other, "demo", "1.0.0", "approved")],
            vec![("demo-1.0.0.tarpkg".into(), other)],
        );
        assert!(install(&db, &dir, &m, "demo", "1.0.0", APP)
            .unwrap_err()
            .contains("مفتاح المراجِع"));

        // 3) غير موقَّعة
        let unsigned = make_zip(&[(
            "manifest.json",
            manifest("demo", "1.0.0").to_string().into_bytes(),
        )]);
        let m = mock_with(
            &rv,
            3,
            vec![entry_for(&unsigned, "demo", "1.0.0", "approved")],
            vec![("demo-1.0.0.tarpkg".into(), unsigned)],
        );
        assert!(install(&db, &dir, &m, "demo", "1.0.0", APP)
            .unwrap_err()
            .contains("غير موقَّعة"));

        // 4) صلاحيات الفهرس لا تطابق manifest
        let mut e = entry_for(&good, "demo", "1.0.0", "approved");
        e["permissions"] = json!(["system.read"]);
        let m = mock_with(
            &rv,
            4,
            vec![e],
            vec![("demo-1.0.0.tarpkg".into(), good.clone())],
        );
        assert!(install(&db, &dir, &m, "demo", "1.0.0", APP)
            .unwrap_err()
            .contains("الصلاحيات"));

        // 5) هوية مختلفة (الحزمة demo لكن الفهرس يدّعي other)
        let mut e = entry_for(&good, "other", "1.0.0", "approved");
        e["permissions"] = json!(["process.run"]);
        let m = mock_with(
            &rv,
            5,
            vec![e],
            vec![("other-1.0.0.tarpkg".into(), good.clone())],
        );
        assert!(install(&db, &dir, &m, "other", "1.0.0", APP)
            .unwrap_err()
            .contains("id/version"));

        // 6) حالات غير معتمدة
        for st in [
            "draft",
            "scanning",
            "review",
            "rejected",
            "suspended",
            "revoked",
        ] {
            let m = mock_with(
                &rv,
                10,
                vec![entry_for(&good, "demo", "1.0.0", st)],
                vec![("demo-1.0.0.tarpkg".into(), good.clone())],
            );
            let err = install(&db, &dir, &m, "demo", "1.0.0", APP).unwrap_err();
            assert!(err.contains(status_ar(st)), "{st}: {err}");
        }

        // 7) إدخال غير موجود
        let m = mock_with(&rv, 11, vec![], vec![]);
        assert!(install(&db, &dir, &m, "demo", "1.0.0", APP).is_err());

        // لم يُثبَّت شيء
        assert!(db.tool_get("demo").unwrap().is_none());
    }

    #[test]
    fn revoked_version_disables_installed_tool_and_blocks_state() {
        let rv = key(1);
        let db = setup(&rv);
        let dir = tmp();
        let pkg = signed_pkg(&manifest("demo", "1.0.0"), &rv);
        let m = mock_with(
            &rv,
            1,
            vec![entry_for(&pkg, "demo", "1.0.0", "approved")],
            vec![("demo-1.0.0.tarpkg".into(), pkg.clone())],
        );
        install(&db, &dir, &m, "demo", "1.0.0", APP).unwrap();
        assert!(db.tool_get("demo").unwrap().unwrap().enabled);

        let mut e = entry_for(&pkg, "demo", "1.0.0", "revoked");
        e["notes"] = json!("يرسل بيانات");
        let m2 = mock_with(&rv, 2, vec![e], vec![]);
        let view = refresh(&db, &m2).unwrap();
        assert_eq!(view.disabled.len(), 1);
        assert!(view.disabled[0].contains("ملغى"));
        assert!(!db.tool_get("demo").unwrap().unwrap().enabled);
        let it = view.items.iter().find(|i| i.entry.id == "demo").unwrap();
        assert_eq!(it.state, "blocked");
        assert_eq!(it.blocked_versions, vec!["1.0.0".to_string()]);
        // تحديث ثانٍ لا يكرّر التعطيل
        let view = refresh(
            &db,
            &mock_with(
                &rv,
                3,
                vec![entry_for(&pkg, "demo", "1.0.0", "revoked")],
                vec![],
            ),
        )
        .unwrap();
        assert!(view.disabled.is_empty());
    }

    #[test]
    fn update_state_and_best_version_selection() {
        let rv = key(1);
        let db = setup(&rv);
        let dir = tmp();
        let p1 = signed_pkg(&manifest("demo", "1.0.0"), &rv);
        let p2 = signed_pkg(&manifest("demo", "1.1.0"), &rv);
        let p3 = signed_pkg(&manifest("demo", "2.0.0"), &rv);
        let m = mock_with(
            &rv,
            1,
            vec![entry_for(&p1, "demo", "1.0.0", "approved")],
            vec![("demo-1.0.0.tarpkg".into(), p1.clone())],
        );
        install(&db, &dir, &m, "demo", "1.0.0", APP).unwrap();
        let entries = vec![
            entry_for(&p1, "demo", "1.0.0", "approved"),
            entry_for(&p2, "demo", "1.1.0", "approved"),
            entry_for(&p3, "demo", "2.0.0", "suspended"),
        ];
        let view = refresh(&db, &mock_with(&rv, 2, entries, vec![])).unwrap();
        let it = view.items.iter().find(|i| i.entry.id == "demo").unwrap();
        assert_eq!(it.entry.version, "1.1.0");
        assert_eq!(it.state, "update");
        assert_eq!(it.blocked_versions, vec!["2.0.0".to_string()]);
        assert!(view.disabled.is_empty());
    }

    #[test]
    fn local_import_is_not_marked_official() {
        let rv = key(1);
        let db = setup(&rv);
        let dir = tmp();
        let local = make_zip(&[(
            "manifest.json",
            manifest("demo", "1.0.0").to_string().into_bytes(),
        )]);
        plugin::install_package(&db, &dir, &local, APP).unwrap();
        let pkg = signed_pkg(&manifest("demo", "1.0.0"), &rv);
        let view = refresh(
            &db,
            &mock_with(
                &rv,
                1,
                vec![entry_for(&pkg, "demo", "1.0.0", "approved")],
                vec![],
            ),
        )
        .unwrap();
        let it = view.items.iter().find(|i| i.entry.id == "demo").unwrap();
        assert!(!it.official);
        assert_eq!(it.state, "installed");
        assert!(official_ids(&db).unwrap().is_empty());
    }

    #[test]
    fn issue_url_is_encoded_and_scoped_to_repo() {
        let rv = key(1);
        let db = setup(&rv);
        let u = issue_url(&db, "report", "demo", "1.0.0").unwrap();
        assert!(u.starts_with("https://github.com/me/tar-market/issues/new?labels=report&title="));
        assert!(!u.contains(' ') && !u.contains('\n'));
        assert!(u.contains("%D8%A8%D9%84%D8%A7%D8%BA")); // «بلاغ»
        assert!(issue_url(&db, "x", "demo", "1.0.0").is_err());
        assert!(issue_url(&db, "report", "../x", "1.0.0").is_err());
    }

    #[test]
    fn http_fetcher_refuses_other_hosts() {
        let err = HttpFetcher
            .get("https://example.com/index.json", 10)
            .unwrap_err();
        assert!(err.contains("غير مسموح"));
        assert!(HttpFetcher
            .get("http://raw.githubusercontent.com/a/b/main/x", 10)
            .is_err());
    }

    #[test]
    fn config_change_resets_seq_and_swaps_trusted_key() {
        let db = Db::open_in_memory().unwrap();
        let a = key(1);
        let b = key(2);
        config_set(&db, REPO, &pub_b64(&a)).unwrap();
        db.setting_set(K_SEQ, "9").unwrap();
        config_set(&db, "me/other", &pub_b64(&b)).unwrap();
        assert_eq!(db.setting_get(K_SEQ).unwrap().as_deref(), Some("0"));
        assert!(db
            .trusted_get(&key_id_of(&a.verifying_key().to_bytes()))
            .unwrap()
            .is_none());
        assert!(db
            .trusted_get(&key_id_of(&b.verifying_key().to_bytes()))
            .unwrap()
            .is_some());
        config_clear(&db).unwrap();
        assert!(config_get(&db).unwrap().is_none());
        assert!(config_set(&db, "bad repo", &pub_b64(&a)).is_err());
        assert!(config_set(&db, REPO, "AAAA").is_err());
    }

    /// اختبار توافق بين اللغات: فهرس وحزمة ولّدتهما tools/market_tool.py (Python) يجب أن يقبلهما Rust.
    #[test]
    fn python_generated_repo_is_accepted_by_rust() {
        let body = include_bytes!("market_fixtures/index.json");
        let sig = include_bytes!("market_fixtures/index.sig");
        let pubkey = std::str::from_utf8(include_bytes!("market_fixtures/reviewer.pub")).unwrap();
        verify_index_sig(body, sig, pubkey).unwrap();
        let ix: Index = serde_json::from_slice(body).unwrap();
        validate_index(&ix).unwrap();
        assert_eq!(ix.seq, 4);
        assert_eq!(ix.packages[0].status, "suspended");
        let (arr, _) = parse_key(pubkey).unwrap();
        let cfg = Config {
            repo: REPO.into(),
            key: pubkey.into(),
            key_id: key_id_of(&arr),
        };
        let pkg = include_bytes!("market_fixtures/demo-1.0.0.tarpkg");
        check_download(pkg, &ix.packages[0], &cfg).unwrap();
        // مفتاح آخر يُرفض
        let other = pub_b64(&key(5));
        assert!(verify_index_sig(body, sig, &other).is_err());
    }
}
