//! سياسة الإعلانات (المواصفة القسم 21). هذه الطبقة تقرّر *هل يُسمح* بإعلان الآن؛ لا تعرض إعلاناً بنفسها.
//!
//! - مزوّد الإعلانات (Start.io) يُدمج في بناء Android فقط: سكربت `tools/android_native.py` يضيف المكتبة وجسر JavaScript
//!   (`window.TarAds`) أثناء بناء الـ APK بمعرّف صاحب الحساب. إن لم يُدمج (فشل السكربت) تتجاهل الواجهة الإعلان
//!   لأن `window.TarAds` غير موجود، ولا يُحتسب شيء. لا إعلانات خارج Android إطلاقاً.
//! - لا إعلانات على غير Android إطلاقاً (ويندوز/Linux/macOS: `provider_available()` = false دائماً).
//! - الحد: 3 إعلانات كحد أقصى في أي نافذة 24 ساعة متحركة (أشدّ من «في اليوم التقويمي» ولا يعتمد على المنطقة الزمنية).
//!   يُحتسب الإعلان عند *منح الإذن* لا عند العرض، فلا يمكن تجاوز الحد حتى لو تكرر الطلب أو فشل العرض.
//! - فاصل أدنى بين إعلانين، وعدم الظهور بعد فتح التطبيق مباشرة، ولا أثناء عملية جارية أو نافذة صلاحيات/تحذير أو جلسة طرفية.
//! - مفتاح مركزي `ads.enabled` يضبطه المشرف فقط.
//! - فشل تحميل الإعلان أو غياب المزوّد لا يمنع أي وظيفة: هذا القرار مستقل تماماً عن بقية التطبيق.

use crate::storage::Db;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const DAILY_CAP: usize = 3;
pub const WINDOW_SECS: u64 = 24 * 3600;
pub const MIN_GAP_SECS: u64 = 15 * 60;
pub const MIN_UPTIME_SECS: u64 = 3 * 60;
/// على Android فقط؛ وجود الجسر الفعلي تتحقق منه الواجهة (window.TarAds) قبل الطلب.
pub const PROVIDER_COMPILED: bool = true;

const K_ENABLED: &str = "ads.enabled";
const K_LOG: &str = "ads.log";

/// لحظات الاستخدام المسموح ربط الإعلان بها (المواصفة 21.8). أي قيمة أخرى تُرفض.
pub const MOMENTS: [&str; 3] = ["task_done", "section_change", "pc_unlock"];

static START: OnceLock<Instant> = OnceLock::new();

pub fn mark_start() {
    let _ = START.set(Instant::now());
}

fn uptime_secs() -> u64 {
    START.get().map(|s| s.elapsed().as_secs()).unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn provider_available() -> bool {
    cfg!(target_os = "android") && PROVIDER_COMPILED
}

/// سياق تعرفه الواجهة وقت الطلب.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctx {
    pub moment: String,
    /// جلسة طرفية ظاهرة أو في المقدمة.
    #[serde(default)]
    pub terminal_active: bool,
    /// نافذة صلاحيات أو تحذير أمني أو تأكيد مفتوحة.
    #[serde(default)]
    pub dialog_open: bool,
    /// أمر أو عملية جارية.
    #[serde(default)]
    pub command_running: bool,
    /// عملية حساسة (إدارة، تثبيت، اقتران...).
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub allow: bool,
    /// رمز السبب (ثابت) ونص عربي للعرض.
    pub code: &'static str,
    pub reason: &'static str,
}

fn deny(code: &'static str, reason: &'static str) -> Decision {
    Decision {
        allow: false,
        code,
        reason,
    }
}

/// قرار نقي (بلا إدخال/إخراج) كي يُختبر بالكامل.
pub fn decide(
    now: u64,
    uptime: u64,
    available: bool,
    enabled: bool,
    log: &[u64],
    ctx: &Ctx,
    busy_ops: usize,
) -> Decision {
    if !available {
        return deny("unavailable", "لا يوجد مزوّد إعلانات في هذا البناء");
    }
    if !enabled {
        return deny("disabled", "الإعلانات معطّلة بمفتاح المشرف");
    }
    if !MOMENTS.contains(&ctx.moment.as_str()) {
        return deny("bad_moment", "لحظة الاستخدام غير مسموح بها للإعلان");
    }
    // فتح الكمبيوتر بالهاتف يحدث عادةً مباشرة بعد تشغيل تطبيق الهاتف، فلا يُطبَّق عليه حد «بعد الفتح».
    // بقية القيود (3 كل 24 ساعة، الفاصل الأدنى، لا عملية جارية) تبقى كما هي.
    if uptime < MIN_UPTIME_SECS && ctx.moment != "pc_unlock" {
        return deny("just_started", "لا إعلانات بعد فتح التطبيق مباشرة");
    }
    if ctx.terminal_active {
        return deny("terminal", "لا إعلانات أثناء جلسة طرفية");
    }
    if ctx.command_running || busy_ops > 0 {
        return deny("busy", "لا إعلانات أثناء تنفيذ أمر أو تدفق");
    }
    if ctx.dialog_open {
        return deny("dialog", "لا إعلانات فوق نوافذ الصلاحيات أو التحذيرات");
    }
    if ctx.sensitive {
        return deny("sensitive", "لا إعلانات أثناء عملية حساسة");
    }
    // سجلات من «المستقبل» تعني تراجع ساعة الجهاز: تبقى محتسبة ونرفض احتياطاً.
    if log.iter().any(|&t| t > now) {
        return deny("clock", "ساعة الجهاز تراجعت؛ أُوقفت الإعلانات احتياطاً");
    }
    let recent: Vec<u64> = log
        .iter()
        .copied()
        .filter(|&t| now - t < WINDOW_SECS)
        .collect();
    if recent.len() >= DAILY_CAP {
        return deny("cap", "بلغ الحد الأقصى (3 إعلانات كل 24 ساعة)");
    }
    if let Some(&last) = recent.iter().max() {
        if now - last < MIN_GAP_SECS {
            return deny("gap", "لم يمضِ الفاصل الأدنى منذ آخر إعلان");
        }
    }
    Decision {
        allow: true,
        code: "ok",
        reason: "مسموح",
    }
}

fn read_log(db: &Db) -> Vec<u64> {
    db.setting_get(K_LOG)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Vec<u64>>(&s).ok())
        .unwrap_or_default()
}

fn write_log(db: &Db, log: &[u64]) -> Result<(), String> {
    db.setting_set(
        K_LOG,
        &serde_json::to_string(log).map_err(|e| e.to_string())?,
    )
}

/// القيمة المخزّنة تغلب دائماً. عند غيابها: معطّل، إلا في بناء Google Play على Android حيث الإعلانات
/// مُعلَنة في المتجر فتُفعَّل افتراضياً (يبقى مفتاح المشرف لإيقافها).
fn enabled_from(setting: Option<&str>, play_default: bool) -> bool {
    match setting {
        Some(v) => v == "1",
        None => play_default,
    }
}

pub fn is_enabled(db: &Db) -> bool {
    enabled_from(
        db.setting_get(K_ENABLED).ok().flatten().as_deref(),
        cfg!(all(feature = "play", target_os = "android")),
    )
}

pub fn set_enabled(db: &Db, on: bool) -> Result<(), String> {
    db.setting_set(K_ENABLED, if on { "1" } else { "0" })?;
    let _ = db.audit_add("ads_switch", "", if on { "on" } else { "off" });
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub available: bool,
    pub enabled: bool,
    pub shown_in_window: usize,
    pub cap: usize,
    pub note: &'static str,
}

pub fn status(db: &Db) -> Status {
    let now = now_secs();
    let shown = read_log(db)
        .iter()
        .filter(|&&t| t <= now && now - t < WINDOW_SECS)
        .count();
    Status {
        available: provider_available(),
        enabled: is_enabled(db),
        shown_in_window: shown,
        cap: DAILY_CAP,
        note: if provider_available() {
            ""
        } else {
            "الإعلانات متاحة على Android فقط"
        },
    }
}

/// يقرّر ويحتسب فوراً إن مُنح الإذن. بلا مزوّد لا يُمنح شيء ولا يُسجَّل شيء.
pub fn request(db: &Db, ctx: &Ctx, busy_ops: usize) -> Decision {
    request_at(
        db,
        ctx,
        busy_ops,
        now_secs(),
        uptime_secs(),
        provider_available(),
    )
}

fn request_at(
    db: &Db,
    ctx: &Ctx,
    busy_ops: usize,
    now: u64,
    uptime: u64,
    available: bool,
) -> Decision {
    let mut log = read_log(db);
    let d = decide(now, uptime, available, is_enabled(db), &log, ctx, busy_ops);
    if d.allow {
        log.retain(|&t| t > now.saturating_sub(WINDOW_SECS));
        log.push(now);
        if write_log(db, &log).is_err() {
            // إن تعذّر حفظ العدّاد لا نسمح (الأحوط لعدم تجاوز الحد)
            return deny("storage", "تعذّر حفظ عدّاد الإعلانات");
        }
        let _ = db.audit_add("ads_allowed", &ctx.moment, "");
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const H: u64 = 3600;

    fn ctx(moment: &str) -> Ctx {
        Ctx {
            moment: moment.into(),
            ..Default::default()
        }
    }
    fn go(log: &[u64], c: &Ctx) -> Decision {
        decide(NOW, 3600, true, true, log, c, 0)
    }

    #[test]
    fn allowed_at_a_good_moment() {
        assert!(go(&[], &ctx("task_done")).allow);
        assert!(go(&[], &ctx("section_change")).allow);
    }

    #[test]
    fn central_switch_and_provider_gate() {
        let c = ctx("task_done");
        assert_eq!(
            decide(NOW, 3600, false, true, &[], &c, 0).code,
            "unavailable"
        );
        assert_eq!(decide(NOW, 3600, true, false, &[], &c, 0).code, "disabled");
    }

    #[test]
    fn unknown_moments_are_refused() {
        for m in ["", "app_start", "page_change", "always", "TASK_DONE"] {
            assert_eq!(go(&[], &ctx(m)).code, "bad_moment", "{m}");
        }
    }

    #[test]
    fn never_right_after_launch() {
        assert_eq!(
            decide(NOW, 10, true, true, &[], &ctx("task_done"), 0).code,
            "just_started"
        );
        assert_eq!(
            decide(
                NOW,
                MIN_UPTIME_SECS - 1,
                true,
                true,
                &[],
                &ctx("task_done"),
                0
            )
            .code,
            "just_started"
        );
        assert!(decide(NOW, MIN_UPTIME_SECS, true, true, &[], &ctx("task_done"), 0).allow);
    }

    #[test]
    fn not_during_terminal_command_dialog_or_sensitive() {
        let mut c = ctx("task_done");
        c.terminal_active = true;
        assert_eq!(go(&[], &c).code, "terminal");
        let mut c = ctx("task_done");
        c.command_running = true;
        assert_eq!(go(&[], &c).code, "busy");
        let mut c = ctx("task_done");
        c.dialog_open = true;
        assert_eq!(go(&[], &c).code, "dialog");
        let mut c = ctx("task_done");
        c.sensitive = true;
        assert_eq!(go(&[], &c).code, "sensitive");
        // عملية جارية في المحرك (تدفق) حتى لو لم تُبلّغ الواجهة
        assert_eq!(
            decide(NOW, 3600, true, true, &[], &ctx("task_done"), 1).code,
            "busy"
        );
    }

    #[test]
    fn cap_is_three_per_rolling_24h() {
        let c = ctx("task_done");
        // ثلاثة خلال الساعات الماضية (بفواصل أكبر من الحد الأدنى)
        let log = [NOW - 20 * H, NOW - 10 * H, NOW - 5 * H];
        assert_eq!(go(&log, &c).code, "cap");
        // بعد أن يخرج الأقدم من النافذة يُسمح بواحد
        let later = decide(NOW + 5 * H, 3600, true, true, &log, &c, 0);
        assert!(later.allow, "{later:?}");
        // اثنان فقط: مسموح
        assert!(go(&[NOW - 10 * H, NOW - 5 * H], &c).allow);
    }

    #[test]
    fn minimum_gap_between_ads() {
        let c = ctx("task_done");
        assert_eq!(go(&[NOW - 60], &c).code, "gap");
        assert_eq!(go(&[NOW - (MIN_GAP_SECS - 1)], &c).code, "gap");
        assert!(go(&[NOW - MIN_GAP_SECS], &c).allow);
    }

    #[test]
    fn clock_rollback_is_refused() {
        assert_eq!(go(&[NOW + 5 * H], &ctx("task_done")).code, "clock");
    }

    #[test]
    fn request_counts_and_never_exceeds_cap_even_when_hammered() {
        let db = Db::open_in_memory().unwrap();
        set_enabled(&db, true).unwrap();
        let c = ctx("task_done");
        let mut allowed = 0;
        // 200 طلباً متتالياً على مدى ~ 40 ساعة بفواصل 12 دقيقة... ثم 20 دقيقة
        let mut now = NOW;
        let mut max_in_window = 0usize;
        let mut times: Vec<u64> = vec![];
        for _ in 0..200 {
            now += 20 * 60;
            if request_at(&db, &c, 0, now, 3600, true).allow {
                allowed += 1;
                times.push(now);
            }
            let in_window = times.iter().filter(|&&t| now - t < WINDOW_SECS).count();
            max_in_window = max_in_window.max(in_window);
        }
        assert!(
            allowed > 3,
            "should allow again after the window slides: {allowed}"
        );
        assert!(max_in_window <= DAILY_CAP, "cap exceeded: {max_in_window}");
        // السجل المخزّن لا ينمو بلا حد
        assert!(read_log(&db).len() <= DAILY_CAP + 1);
    }

    #[test]
    fn without_provider_nothing_is_allowed_or_recorded() {
        let db = Db::open_in_memory().unwrap();
        set_enabled(&db, true).unwrap();
        let d = request_at(&db, &ctx("task_done"), 0, NOW, 3600, false);
        assert_eq!(d.code, "unavailable");
        assert!(read_log(&db).is_empty());
        // خارج Android (وبيئة الاختبار) لا مزوّد: القرار الفعلي دائماً رفض
        assert!(!provider_available());
        assert!(!request(&db, &ctx("task_done"), 0).allow);
    }

    #[test]
    fn switch_defaults_off_and_status_reports() {
        let db = Db::open_in_memory().unwrap();
        assert!(!is_enabled(&db));
        let st = status(&db);
        assert!(!st.available && !st.enabled);
        assert_eq!(st.cap, 3);
        assert_eq!(st.shown_in_window, 0);
        set_enabled(&db, true).unwrap();
        assert!(is_enabled(&db));
    }

    #[test]
    fn corrupt_log_is_treated_as_empty_not_a_crash() {
        let db = Db::open_in_memory().unwrap();
        db.setting_set(K_LOG, "not json").unwrap();
        assert!(read_log(&db).is_empty());
    }

    #[test]
    fn pc_unlock_moment_skips_only_the_uptime_floor() {
        let c = ctx("pc_unlock");
        assert!(decide(100_000, 5, true, true, &[], &c, 0).allow);
        // الحد اليومي والفاصل يسريان عليه
        let log = [100_000 - 60];
        assert_eq!(decide(100_000, 5, true, true, &log, &c, 0).code, "gap");
        let log3 = [97_000, 98_000, 99_000]; // داخل نافذة 24 ساعة والفاصل منقضٍ
        assert_eq!(decide(100_000, 5, true, true, &log3, &c, 0).code, "cap");
        // غيره من اللحظات ما زال يخضع لحد بعد الفتح
        assert_eq!(
            decide(100_000, 5, true, true, &[], &ctx("task_done"), 0).code,
            "just_started"
        );
    }

    #[test]
    fn stored_switch_wins_and_default_depends_on_play_build() {
        assert!(!enabled_from(None, false));
        assert!(enabled_from(None, true));
        assert!(enabled_from(Some("1"), false));
        assert!(!enabled_from(Some("0"), true)); // المشرف أوقفها صراحة
        assert!(!enabled_from(Some("garbage"), true));
    }
}
