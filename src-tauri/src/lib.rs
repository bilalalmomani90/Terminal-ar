mod admin;
mod ads;
mod connection;
mod discovery;
mod market;
mod plugin;
mod security;
mod storage;
mod studio;
mod terminal;
mod workflow;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use plugin::{InstallOutcome, ToolInfo};
use security::{LabReport, RunPlan, SecurityInfo};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use storage::{AuditRow, Db, FrequentEntry, HistoryEntry, SessionRow, ToolLogRow, TrustedKey};
use studio::{
    BuildOutcome, ProjectInfo, Runtimes, TestReport, TextCheck, TreeEntry, ValidateReport,
};
use tauri::{AppHandle, Emitter, Manager, State};
use terminal::{default_cwd, shell_spec, SessionEvent, Sink, TerminalEngine};

#[derive(Serialize, Clone)]
struct OutputPayload {
    id: String,
    /// بايتات الخرج الخام بترميز base64 (حتى لا تنقطع أحرف UTF-8 متعددة البايتات).
    data: String,
}

#[derive(Serialize, Clone)]
struct ExitPayload {
    id: String,
    code: Option<u32>,
}

#[derive(Serialize)]
struct AppInfo {
    name: &'static str,
    version: &'static str,
    build: &'static str,
    /// windows | linux | macos
    os: &'static str,
}

fn make_sink(app: AppHandle) -> Sink {
    Arc::new(move |ev| match ev {
        SessionEvent::Output { id, data } => {
            let _ = app.emit(
                "terminal-output",
                OutputPayload {
                    id,
                    data: B64.encode(data),
                },
            );
        }
        SessionEvent::Exit { id, code } => {
            if let Some(db) = app.try_state::<Db>() {
                let _ = db.session_ended(&id, code);
            }
            let _ = app.emit("terminal-exit", ExitPayload { id, code });
        }
    })
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        name: "Terminal AR",
        version: env!("CARGO_PKG_VERSION"),
        build: env!("TAR_BUILD"),
        os: std::env::consts::OS,
    }
}

// ---------------- الطرفية ----------------

#[tauri::command]
async fn terminal_open(
    app: AppHandle,
    engine: State<'_, TerminalEngine>,
    db: State<'_, Db>,
    tools: State<'_, ToolsDir>,
    conn: State<'_, Arc<connection::Conn>>,
    kind: String,
    cols: u16,
    rows: u16,
    cwd: Option<String>,
) -> Result<String, String> {
    if lock_enabled(&db) && !conn.lock_status().unlocked {
        return Err("الكمبيوتر مقفل: اقرأ رمز QR من تطبيق الهاتف".into());
    }
    // على Android لا يوجد HOME: مجلد بيانات التطبيق هو المكان الوحيد القابل للكتابة
    let cwd = cwd
        .map(PathBuf::from)
        .or_else(default_cwd)
        .or_else(|| tools.0.parent().map(|p| p.to_path_buf()));
    let spec = shell_spec(&kind, cwd)?;
    let id = engine.open(&spec, cols, rows, make_sink(app))?;
    let _ = db.session_started(&id, &kind);
    Ok(id)
}

#[tauri::command]
async fn terminal_write(
    engine: State<'_, TerminalEngine>,
    id: String,
    data: String,
) -> Result<(), String> {
    engine.write(&id, data.as_bytes())
}

#[tauri::command]
async fn terminal_resize(
    engine: State<'_, TerminalEngine>,
    id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    engine.resize(&id, cols, rows)
}

#[tauri::command]
async fn terminal_kill(engine: State<'_, TerminalEngine>, id: String) -> Result<(), String> {
    engine.kill(&id)
}

#[tauri::command]
async fn terminal_close(engine: State<'_, TerminalEngine>, id: String) -> Result<(), String> {
    engine.close(&id)
}

// ---------------- التخزين ----------------

#[tauri::command]
async fn setting_get(db: State<'_, Db>, key: String) -> Result<Option<String>, String> {
    db.setting_get(&key)
}

#[tauri::command]
async fn setting_set(db: State<'_, Db>, key: String, value: String) -> Result<(), String> {
    db.setting_set(&key, &value)
}

#[tauri::command]
async fn favorites_list(db: State<'_, Db>) -> Result<Vec<String>, String> {
    db.favorites_list()
}

#[tauri::command]
async fn favorite_toggle(db: State<'_, Db>, item_id: String) -> Result<bool, String> {
    db.favorite_toggle(&item_id)
}

#[tauri::command]
async fn history_add(
    db: State<'_, Db>,
    item_id: Option<String>,
    command: String,
    shell: String,
) -> Result<(), String> {
    db.history_add(item_id.as_deref(), &command, &shell)
}

#[tauri::command]
async fn history_recent(db: State<'_, Db>, limit: u32) -> Result<Vec<HistoryEntry>, String> {
    db.history_recent(limit)
}

#[tauri::command]
async fn history_frequent(db: State<'_, Db>, limit: u32) -> Result<Vec<FrequentEntry>, String> {
    db.history_frequent(limit)
}

#[tauri::command]
async fn history_clear(db: State<'_, Db>) -> Result<(), String> {
    db.history_clear()
}

#[tauri::command]
async fn sessions_recent(db: State<'_, Db>, limit: u32) -> Result<Vec<SessionRow>, String> {
    db.sessions_recent(limit)
}

// ---------------- الأدوات (Plugin Engine) ----------------

/// مجلد الأدوات المثبّتة داخل بيانات التطبيق (مجلد منفصل لكل أداة).
struct ToolsDir(PathBuf);

#[tauri::command]
async fn tools_list(db: State<'_, Db>) -> Result<Vec<ToolInfo>, String> {
    plugin::list(&db)
}

#[tauri::command]
async fn tool_install(
    db: State<'_, Db>,
    dir: State<'_, ToolsDir>,
    data: String,
) -> Result<InstallOutcome, String> {
    let bytes = B64
        .decode(data.as_bytes())
        .map_err(|_| "بيانات الحزمة غير صالحة".to_string())?;
    plugin::install_package(&db, &dir.0, &bytes, env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
async fn tool_uninstall(
    db: State<'_, Db>,
    dir: State<'_, ToolsDir>,
    id: String,
) -> Result<(), String> {
    plugin::uninstall(&db, &dir.0, &id)
}

#[tauri::command]
async fn tool_set_enabled(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    adm.require()
        .map_err(|_| "تفعيل/إيقاف الأدوات من صلاحيات المشرف".to_string())?;
    plugin::set_enabled(&db, &id, enabled)
}

#[tauri::command]
async fn tool_log_add(
    db: State<'_, Db>,
    tool_id: String,
    level: String,
    message: String,
) -> Result<(), String> {
    if !["info", "warn", "error"].contains(&level.as_str()) {
        return Err("invalid log level".into());
    }
    db.tool_log_add(&tool_id, &level, &message)
}

#[tauri::command]
async fn tool_log_recent(
    db: State<'_, Db>,
    tool_id: String,
    limit: u32,
) -> Result<Vec<ToolLogRow>, String> {
    db.tool_log_recent(&tool_id, limit)
}

// ---------------- الأمان (Security Engine) ----------------

#[tauri::command]
async fn tool_security(db: State<'_, Db>, id: String) -> Result<SecurityInfo, String> {
    security::security_info(&db, &id)
}

#[tauri::command]
async fn tool_set_grants(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    id: String,
    permissions: Vec<String>,
) -> Result<(), String> {
    adm.require()
        .map_err(|_| "الموافقة على صلاحيات الأدوات من صلاحيات المشرف".to_string())?;
    security::set_grants(&db, &id, &permissions)
}

/// القرار النهائي لتشغيل إجراء: الصلاحيات والفحص الساكن والتأكيد المطلوب. الواجهة تنفذ ما تعيده فقط.
#[tauri::command]
async fn tool_plan_run(
    db: State<'_, Db>,
    dir: State<'_, ToolsDir>,
    tool_id: String,
    action_id: String,
) -> Result<RunPlan, String> {
    security::plan_run(&db, &dir.0, &tool_id, &action_id)
}

#[tauri::command]
async fn tool_run_commit(
    db: State<'_, Db>,
    tool_id: String,
    action_id: String,
) -> Result<(), String> {
    db.audit_add("run", &tool_id, &action_id)
}

#[tauri::command]
async fn tool_rescan(db: State<'_, Db>, id: String) -> Result<LabReport, String> {
    security::rescan(&db, &id)
}

#[tauri::command]
async fn trusted_list(db: State<'_, Db>) -> Result<Vec<TrustedKey>, String> {
    db.trusted_list()
}

#[tauri::command]
async fn trusted_add(
    db: State<'_, Db>,
    name: String,
    public_key: String,
) -> Result<TrustedKey, String> {
    security::trust_add(&db, &name, &public_key)
}

#[tauri::command]
async fn trusted_remove(db: State<'_, Db>, key_id: String) -> Result<(), String> {
    security::trust_remove(&db, &key_id)
}

#[tauri::command]
async fn audit_recent(db: State<'_, Db>, limit: u32) -> Result<Vec<AuditRow>, String> {
    db.audit_recent(limit)
}

// ---------------- Workflow (المرحلة 6) ----------------

/// التشغيلات الجارية: معرّف التشغيل ← (معرّف التدفق، علم الإيقاف).
#[derive(Default)]
struct WorkflowRuns(Mutex<HashMap<i64, (String, Arc<AtomicBool>)>>);

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WfEvent {
    run_id: i64,
    kind: String,
    step_id: String,
    status: String,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WfCheck {
    ok: bool,
    id: Option<String>,
    name: Option<String>,
    diagnostics: Vec<plugin::Diag>,
    /// النص بعد إصلاح الفواصل الزائدة تلقائياً (إن لزم)
    fixed: Option<String>,
}

fn parse_wf(text: &str) -> (Result<workflow::Workflow, plugin::Diag>, Option<String>) {
    match workflow::parse(text) {
        Ok(w) => (Ok(w), None),
        Err(d) => match studio::fix_json_text(text) {
            Ok(f) if f != text => match workflow::parse(&f) {
                Ok(w) => (Ok(w), Some(f)),
                Err(_) => (Err(d), None),
            },
            _ => (Err(d), None),
        },
    }
}

#[tauri::command]
async fn workflow_list(db: State<'_, Db>) -> Result<Vec<storage::WfRow>, String> {
    db.wf_list()
}

#[tauri::command]
async fn workflow_check(text: String) -> Result<WfCheck, String> {
    let (wf, fixed) = parse_wf(&text);
    Ok(match wf {
        Err(d) => WfCheck {
            ok: false,
            id: None,
            name: None,
            diagnostics: vec![d],
            fixed: None,
        },
        Ok(w) => {
            let diagnostics = workflow::diagnose(&w);
            WfCheck {
                ok: diagnostics.iter().all(|d| d.severity != "error"),
                id: Some(w.id),
                name: Some(w.name),
                diagnostics,
                fixed,
            }
        }
    })
}

#[tauri::command]
async fn workflow_save(db: State<'_, Db>, text: String) -> Result<storage::WfRow, String> {
    let (wf, _) = parse_wf(&text);
    let wf = wf.map_err(|d| d.message)?;
    let errs: Vec<String> = workflow::diagnose(&wf)
        .into_iter()
        .filter(|d| d.severity == "error")
        .map(|d| format!("{}: {}", d.path, d.message))
        .collect();
    if !errs.is_empty() {
        return Err(errs.join("\n"));
    }
    let body = serde_json::to_string_pretty(&wf).map_err(|e| e.to_string())? + "\n";
    db.wf_put(&wf.id, &wf.name, &body)?;
    db.audit_add("workflow_save", &wf.id, "")?;
    db.wf_get(&wf.id)?
        .ok_or_else(|| "تعذّر قراءة التدفق بعد الحفظ".to_string())
}

#[tauri::command]
async fn workflow_delete(db: State<'_, Db>, id: String) -> Result<(), String> {
    if !db.wf_delete(&id)? {
        return Err("التدفق غير موجود".into());
    }
    workflow::clear_grants(&db, &id)?;
    db.audit_add("workflow_delete", &id, "")
}

fn load_wf(db: &Db, id: &str) -> Result<workflow::Workflow, String> {
    let row = db
        .wf_get(id)?
        .ok_or_else(|| "التدفق غير موجود".to_string())?;
    workflow::parse(&row.body).map_err(|d| d.message)
}

#[tauri::command]
async fn workflow_plan(
    db: State<'_, Db>,
    dir: State<'_, ToolsDir>,
    id: String,
) -> Result<workflow::WfPlan, String> {
    let wf = load_wf(&db, &id)?;
    workflow::plan(&db, &dir.0, &wf)
}

#[tauri::command]
async fn workflow_grants_set(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    id: String,
    permissions: Vec<String>,
) -> Result<(), String> {
    adm.require()
        .map_err(|_| "الموافقة على صلاحيات التدفقات من صلاحيات المشرف".to_string())?;
    if db.wf_get(&id)?.is_none() {
        return Err("التدفق غير موجود".into());
    }
    workflow::set_grants(&db, &id, &permissions)
}

#[tauri::command]
async fn workflow_run(
    app: AppHandle,
    db: State<'_, Db>,
    dir: State<'_, ToolsDir>,
    runs: State<'_, WorkflowRuns>,
    id: String,
) -> Result<i64, String> {
    let wf = load_wf(&db, &id)?;
    // البوابة الأصلية: لا تشغيل بصلاحيات غير ممنوحة
    let plan = workflow::plan(&db, &dir.0, &wf)?;
    if !plan.missing.is_empty() {
        let _ = db.audit_add("run_blocked", &format!("wf:{id}"), &plan.missing.join(","));
        return Err(format!(
            "[PERMISSIONS] التدفق يتطلب صلاحيات غير معتمدة: {}",
            plan.missing.join("، ")
        ));
    }
    let prepared = workflow::prepare(&db, &dir.0, &wf)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let run_id = {
        let mut m = runs.0.lock().map_err(|_| "قفل داخلي".to_string())?;
        if m.values().any(|(w, _)| w == &id) {
            return Err("هذا التدفق يعمل الآن".into());
        }
        let run_id = db.wf_run_start(&id)?;
        m.insert(run_id, (id.clone(), cancel.clone()));
        run_id
    };
    db.audit_add("workflow_start", &id, &format!("run {run_id}"))?;

    let app2 = app.clone();
    let items = prepared.items;
    let vars = wf.variables.clone();
    let wf_id = wf.id.clone();
    std::thread::spawn(move || {
        let emit_app = app2.clone();
        let emit = move |kind: &str, step: &str, status: &str, text: &str| {
            let _ = emit_app.emit(
                "workflow-event",
                WfEvent {
                    run_id,
                    kind: kind.into(),
                    step_id: step.into(),
                    status: status.into(),
                    text: text.into(),
                },
            );
        };
        let rep = workflow::run_prepared(
            &wf_id,
            &items,
            &vars,
            &workflow::ProcessExec,
            &cancel,
            &emit,
        );
        let db = app2.state::<Db>();
        let report = serde_json::to_string(&rep).unwrap_or_default();
        let _ = db.wf_run_finish(run_id, &rep.status, &report);
        let _ = db.audit_add(
            "workflow_end",
            &wf_id,
            &format!("run {run_id}: {}", rep.status),
        );
        if let Ok(mut m) = app2.state::<WorkflowRuns>().0.lock() {
            m.remove(&run_id);
        }
        let _ = app2.emit(
            "workflow-event",
            WfEvent {
                run_id,
                kind: "run_end".into(),
                step_id: String::new(),
                status: rep.status.clone(),
                text: String::new(),
            },
        );
    });
    Ok(run_id)
}

#[tauri::command]
async fn workflow_stop(
    db: State<'_, Db>,
    runs: State<'_, WorkflowRuns>,
    run_id: i64,
) -> Result<(), String> {
    let m = runs.0.lock().map_err(|_| "قفل داخلي".to_string())?;
    match m.get(&run_id) {
        Some((wf, flag)) => {
            flag.store(true, Ordering::SeqCst);
            let _ = db.audit_add("workflow_stop", wf, &format!("run {run_id}"));
            Ok(())
        }
        None => Err("هذا التشغيل غير جارٍ".into()),
    }
}

#[tauri::command]
async fn workflow_runs(
    db: State<'_, Db>,
    id: String,
    limit: u32,
) -> Result<Vec<storage::WfRunRow>, String> {
    db.wf_runs_recent(&id, limit.min(50))
}

// ---------------- الأجهزة والاتصال (المرحلة 7) ----------------

struct AppHost {
    app: AppHandle,
}

#[derive(Serialize, Clone)]
struct ConnEvent {
    kind: String,
    id: u64,
    text: String,
}

impl connection::Host for AppHost {
    fn db(&self) -> &Db {
        self.app.state::<Db>().inner()
    }
    fn tools_dir(&self) -> PathBuf {
        self.app.state::<ToolsDir>().0.clone()
    }
    fn notify(&self, kind: &str, id: u64, text: &str) {
        let _ = self.app.emit(
            "conn-event",
            ConnEvent {
                kind: kind.into(),
                id,
                text: text.into(),
            },
        );
    }
}

fn need_admin(adm: &admin::AdminState) -> Result<(), String> {
    adm.require()
        .map_err(|_| "إدارة الأجهزة من صلاحيات المشرف".to_string())
}

#[tauri::command]
async fn conn_status(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
) -> Result<connection::ConnStatus, String> {
    need_admin(&adm)?;
    Ok(conn.status())
}

#[tauri::command]
async fn conn_listen(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    db: State<'_, Db>,
    app: AppHandle,
    enable: bool,
    lan: bool,
) -> Result<(), String> {
    need_admin(&adm)?;
    if enable {
        let port = conn.listen_start(Arc::new(AppHost { app }), connection::DEFAULT_PORT, lan)?;
        db.audit_add("conn_listen", "host", &format!("port {port}, lan {lan}"))?;
    } else {
        conn.listen_stop();
        db.audit_add("conn_listen", "host", "stopped")?;
    }
    Ok(())
}

#[tauri::command]
async fn conn_pairing(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    db: State<'_, Db>,
    enable: bool,
) -> Result<Option<String>, String> {
    need_admin(&adm)?;
    if enable {
        let code = conn.pairing_start()?;
        db.audit_add("pairing_mode", "host", "on")?;
        Ok(Some(code))
    } else {
        conn.pairing_cancel();
        Ok(None)
    }
}

#[tauri::command]
async fn conn_pending(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
) -> Result<Vec<connection::PendingPair>, String> {
    need_admin(&adm)?;
    Ok(conn.pending())
}

#[tauri::command]
async fn conn_decide(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    id: u64,
    accept: bool,
) -> Result<(), String> {
    need_admin(&adm)?;
    conn.decide(id, accept)
}

#[tauri::command]
async fn conn_devices(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
) -> Result<Vec<storage::DeviceRow>, String> {
    need_admin(&adm)?;
    db.device_list()
}

#[tauri::command]
async fn conn_unpair(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    fingerprint: String,
) -> Result<(), String> {
    need_admin(&adm)?;
    if !db.device_delete(&fingerprint)? {
        return Err("الجهاز غير موجود".into());
    }
    db.audit_add("unpair", &fingerprint, "")
}

#[tauri::command]
async fn conn_catalog(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
) -> Result<Vec<connection::RItem>, String> {
    need_admin(&adm)?;
    connection::catalog(&db)
}

#[tauri::command]
async fn conn_allow_get(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    fingerprint: String,
) -> Result<Vec<String>, String> {
    need_admin(&adm)?;
    db.allow_get(&fingerprint)
}

#[tauri::command]
async fn conn_allow_set(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    fingerprint: String,
    items: Vec<String>,
) -> Result<(), String> {
    need_admin(&adm)?;
    match db.device_get(&fingerprint)? {
        Some(d) if d.role == "controller" => {}
        _ => return Err("الجهاز غير مقترن كجهاز يتحكم بك".into()),
    }
    db.allow_set(&fingerprint, &items)?;
    db.audit_add("allow_set", &fingerprint, &items.join(","))
}

/// يبدأ اقتراناً كمبادر. يعيد معرّف الطلب فوراً؛ النتيجة عبر حدث conn-event.
#[tauri::command]
async fn conn_pair_start(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    app: AppHandle,
    addr: String,
    code: String,
) -> Result<u64, String> {
    need_admin(&adm)?;
    let id = 1_000_000 + COUNTER.fetch_add(1, Ordering::SeqCst);
    let conn2 = conn.inner().clone();
    std::thread::spawn(move || {
        let host = AppHost { app: app.clone() };
        match conn2.pair_client(&host, id, &addr, &code) {
            Ok(d) => connection::Host::notify(&host, "pair_done", id, &d.name),
            Err(e) => connection::Host::notify(&host, "pair_failed", id, &e),
        }
    });
    Ok(id)
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[tauri::command]
async fn conn_pair_confirm(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    id: u64,
    accept: bool,
) -> Result<(), String> {
    need_admin(&adm)?;
    conn.client_confirm(id, accept)
}

#[tauri::command]
async fn conn_remote_list(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    app: AppHandle,
    fingerprint: String,
    addr: Option<String>,
) -> Result<Vec<connection::RItem>, String> {
    need_admin(&adm)?;
    let conn2 = conn.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        conn2.remote_list(app.state::<Db>().inner(), &fingerprint, addr.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteRun {
    ok: bool,
    status: String,
    output: String,
}

#[tauri::command]
async fn conn_remote_run(
    adm: State<'_, admin::AdminState>,
    conn: State<'_, Arc<connection::Conn>>,
    app: AppHandle,
    fingerprint: String,
    item: String,
    addr: Option<String>,
) -> Result<RemoteRun, String> {
    need_admin(&adm)?;
    let conn2 = conn.inner().clone();
    let (ok, status, output) = tauri::async_runtime::spawn_blocking(move || {
        conn2.remote_run(
            app.state::<Db>().inner(),
            &fingerprint,
            &item,
            addr.as_deref(),
        )
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(RemoteRun { ok, status, output })
}

// ---------------- المشرف (مخفي) ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminInfo {
    version: String,
    data_dir: String,
    tools_dir: String,
    studio_dir: String,
    db_bytes: u64,
    counts: Vec<(String, i64)>,
}

#[tauri::command]
async fn admin_probe(st: State<'_, admin::AdminState>, secret: String) -> Result<bool, String> {
    let st = st.inner().clone();
    tauri::async_runtime::spawn_blocking(move || st.probe(&secret))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn admin_unlock(
    st: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    secret: String,
    name: String,
    year: String,
) -> Result<(), String> {
    let h = st.inner().clone();
    let r = tauri::async_runtime::spawn_blocking(move || h.unlock(&secret, &name, &year))
        .await
        .map_err(|e| e.to_string())?;
    match &r {
        Ok(()) => {
            let _ = db.audit_add("admin_unlock", "admin", "نجاح");
        }
        Err(_) => {
            let _ = db.audit_add("admin_unlock_fail", "admin", "محاولة فاشلة");
        }
    }
    r
}

#[tauri::command]
async fn admin_lock(st: State<'_, admin::AdminState>) -> Result<(), String> {
    st.lock();
    Ok(())
}

#[tauri::command]
async fn admin_status(st: State<'_, admin::AdminState>) -> Result<bool, String> {
    Ok(st.is_unlocked())
}

#[tauri::command]
async fn admin_info(
    st: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    tools: State<'_, ToolsDir>,
    studio: State<'_, StudioDir>,
) -> Result<AdminInfo, String> {
    st.require()?;
    let data = tools
        .0
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    let db_bytes = std::fs::metadata(data.join("terminal-ar.db"))
        .map(|m| m.len())
        .unwrap_or(0);
    let mut counts = Vec::new();
    for t in [
        "tools",
        "tool_log",
        "history",
        "sessions",
        "favorites",
        "trusted_keys",
        "audit_log",
    ] {
        counts.push((t.to_string(), db.count_rows(t)?));
    }
    Ok(AdminInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: data.display().to_string(),
        tools_dir: tools.0.display().to_string(),
        studio_dir: studio.0.display().to_string(),
        db_bytes,
        counts,
    })
}

#[tauri::command]
async fn admin_open_data_dir(
    st: State<'_, admin::AdminState>,
    tools: State<'_, ToolsDir>,
) -> Result<(), String> {
    st.require()?;
    let data = tools.0.parent().ok_or("مسار غير معروف")?.to_path_buf();
    #[cfg(windows)]
    {
        std::process::Command::new("explorer")
            .arg(&data)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        std::process::Command::new(opener)
            .arg(&data)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("تعذّر فتح المجلد ({opener}): {e}"))
    }
}

#[tauri::command]
async fn admin_rescan_all(
    st: State<'_, admin::AdminState>,
    db: State<'_, Db>,
) -> Result<Vec<(String, String)>, String> {
    st.require()?;
    let mut out = Vec::new();
    for t in db.tools_list()? {
        let r = match security::rescan(&db, &t.id) {
            Ok(rep) => rep.risk,
            Err(e) => format!("خطأ: {e}"),
        };
        out.push((t.id, r));
    }
    let _ = db.audit_add("admin_rescan_all", "admin", &format!("{} أداة", out.len()));
    Ok(out)
}

#[tauri::command]
async fn admin_audit(
    st: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    limit: u32,
) -> Result<Vec<AuditRow>, String> {
    st.require()?;
    db.audit_recent(limit.min(1000))
}

// ---------------- Studio (المرحلة 5) ----------------

/// مجلد مشاريع الاستوديو داخل بيانات التطبيق.
struct StudioDir(PathBuf);

#[tauri::command]
async fn studio_projects(dir: State<'_, StudioDir>) -> Result<Vec<ProjectInfo>, String> {
    studio::list(&dir.0)
}

#[tauri::command]
async fn studio_create(
    dir: State<'_, StudioDir>,
    id: String,
    name: String,
) -> Result<ProjectInfo, String> {
    studio::create(&dir.0, &id, &name)
}

#[tauri::command]
async fn studio_import(
    dir: State<'_, StudioDir>,
    data: String,
    id: Option<String>,
) -> Result<ProjectInfo, String> {
    let bytes = B64
        .decode(data.as_bytes())
        .map_err(|_| "بيانات الملف غير صالحة".to_string())?;
    studio::import_zip(&dir.0, &bytes, id.as_deref())
}

#[tauri::command]
async fn studio_delete(dir: State<'_, StudioDir>, id: String) -> Result<(), String> {
    studio::delete(&dir.0, &id)
}

#[tauri::command]
async fn studio_tree(dir: State<'_, StudioDir>, id: String) -> Result<Vec<TreeEntry>, String> {
    studio::tree(&dir.0, &id)
}

#[tauri::command]
async fn studio_read(
    dir: State<'_, StudioDir>,
    id: String,
    path: String,
) -> Result<String, String> {
    studio::read_file(&dir.0, &id, &path)
}

#[tauri::command]
async fn studio_write(
    dir: State<'_, StudioDir>,
    id: String,
    path: String,
    content: String,
) -> Result<(), String> {
    studio::write_file(&dir.0, &id, &path, &content)
}

#[tauri::command]
async fn studio_mkdir(dir: State<'_, StudioDir>, id: String, path: String) -> Result<(), String> {
    studio::make_dir(&dir.0, &id, &path)
}

#[tauri::command]
async fn studio_delete_path(
    dir: State<'_, StudioDir>,
    id: String,
    path: String,
) -> Result<(), String> {
    studio::delete_path(&dir.0, &id, &path)
}

#[tauri::command]
async fn studio_rename(
    dir: State<'_, StudioDir>,
    id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    studio::rename_path(&dir.0, &id, &from, &to)
}

#[tauri::command]
async fn studio_validate(dir: State<'_, StudioDir>, id: String) -> Result<ValidateReport, String> {
    studio::validate(&dir.0, &id, env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
async fn studio_build(dir: State<'_, StudioDir>, id: String) -> Result<BuildOutcome, String> {
    studio::build(&dir.0, &id, env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
async fn studio_test(dir: State<'_, StudioDir>, id: String) -> Result<TestReport, String> {
    studio::test(&dir.0, &id, env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
async fn studio_install(
    db: State<'_, Db>,
    studio_dir: State<'_, StudioDir>,
    tools: State<'_, ToolsDir>,
    id: String,
) -> Result<InstallOutcome, String> {
    studio::install(&studio_dir.0, &db, &tools.0, &id, env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
async fn studio_format(dir: State<'_, StudioDir>, id: String) -> Result<(), String> {
    studio::format_manifest(&dir.0, &id)
}

// ---------------- الإعلانات (سياسة فقط؛ لا مزوّد في هذا البناء) ----------------

#[tauri::command]
async fn ads_status(db: State<'_, Db>) -> Result<ads::Status, String> {
    Ok(ads::status(&db))
}

#[tauri::command]
async fn ads_request(
    db: State<'_, Db>,
    runs: State<'_, WorkflowRuns>,
    ctx: ads::Ctx,
) -> Result<ads::Decision, String> {
    let busy = runs.0.lock().map(|m| m.len()).unwrap_or(1);
    Ok(ads::request(&db, &ctx, busy))
}

#[tauri::command]
async fn ads_set_enabled(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    on: bool,
) -> Result<(), String> {
    adm.require()
        .map_err(|_| "مفتاح الإعلانات من صلاحيات المشرف".to_string())?;
    ads::set_enabled(&db, on)
}

// ---------------- قفل الكمبيوتر بالهاتف ----------------

const K_LOCK: &str = "lock.enabled";

/// القفل لسطح المكتب فقط (على Android لا معنى له: الهاتف هو المفتاح).
fn lock_enabled(db: &Db) -> bool {
    !cfg!(target_os = "android") && db.setting_get(K_LOCK).ok().flatten().as_deref() == Some("1")
}

/// إعلان mDNS لشاشة القفل (يعمل فقط ما دام الكمبيوتر مقفلاً).
#[derive(Default)]
struct AdvState(std::sync::Mutex<Option<discovery::Advertiser>>);

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LockInfo {
    enabled: bool,
    supported: bool,
    status: connection::LockStatus,
}

#[tauri::command]
async fn lock_info(
    db: State<'_, Db>,
    conn: State<'_, Arc<connection::Conn>>,
    adv: State<'_, AdvState>,
) -> Result<LockInfo, String> {
    let enabled = lock_enabled(&db);
    let status = conn.lock_status();
    if !enabled || status.unlocked {
        // لا داعي لإعلان الجهاز على الشبكة وهو غير مقفل
        if let Ok(mut g) = adv.0.lock() {
            g.take();
        }
    }
    Ok(LockInfo {
        enabled,
        supported: !cfg!(target_os = "android"),
        status,
    })
}

#[tauri::command]
async fn lock_set_enabled(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    conn: State<'_, Arc<connection::Conn>>,
    adv: State<'_, AdvState>,
    on: bool,
) -> Result<(), String> {
    need_admin(&adm)?;
    db.setting_set(K_LOCK, if on { "1" } else { "0" })?;
    conn.lock_relock();
    if !on {
        if let Ok(mut g) = adv.0.lock() {
            g.take();
        }
    }
    db.audit_add("lock_enabled", "admin", if on { "on" } else { "off" })?;
    Ok(())
}

/// رمز QR جديد لشاشة القفل. يشغّل الاستماع على الشبكة المحلية إن لم يكن شغالاً.
#[tauri::command]
async fn lock_begin(
    db: State<'_, Db>,
    conn: State<'_, Arc<connection::Conn>>,
    adv: State<'_, AdvState>,
    app: AppHandle,
) -> Result<connection::LockOffer, String> {
    if !lock_enabled(&db) {
        return Err("القفل غير مفعّل".into());
    }
    let st = conn.status();
    if st.listening && !st.lan {
        conn.listen_stop();
    }
    if !conn.status().listening {
        conn.listen_start(Arc::new(AppHost { app }), connection::DEFAULT_PORT, true)?;
    }
    let offer = conn.lock_begin()?;
    // إعلان mDNS (اسم الكمبيوتر والمنفذ فقط، بلا الرمز): تعثّره لا يمنع QR
    if let Ok(mut g) = adv.0.lock() {
        if g.is_none() {
            let addrs = discovery::local_addrs();
            *g = discovery::Advertiser::start(&offer.name, offer.port, &addrs).ok();
        }
    }
    Ok(offer)
}

#[tauri::command]
async fn lock_emergency(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    conn: State<'_, Arc<connection::Conn>>,
    secret: String,
    name: String,
    year: String,
) -> Result<(), String> {
    let h = adm.inner().clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let was = h.is_unlocked();
        let r = h.unlock(&secret, &name, &year);
        if !was {
            h.lock(); // الطوارئ لا تفتح صفحة المشرف
        }
        r
    })
    .await
    .map_err(|e| e.to_string())?;
    match r {
        Ok(()) => {
            conn.lock_emergency();
            let _ = db.audit_add("lock_emergency", "admin", "نجاح");
            Ok(())
        }
        Err(e) => {
            let _ = db.audit_add("lock_emergency_fail", "admin", "محاولة فاشلة");
            Err(e)
        }
    }
}

#[tauri::command]
async fn lock_relock(conn: State<'_, Arc<connection::Conn>>) -> Result<(), String> {
    conn.lock_relock();
    Ok(())
}

/// جهة الهاتف: الاتصال بالكمبيوتر بما قُرئ من QR.
#[tauri::command]
async fn lock_phone_connect(
    conn: State<'_, Arc<connection::Conn>>,
    app: AppHandle,
    addr: String,
    code: String,
) -> Result<String, String> {
    // نقبل شبكة محلية أو VPN فقط (لا عناوين عامة)
    let list = discovery::parse_addr_list(&addr)?
        .iter()
        .map(|(ip, port)| format!("{ip}:{port}"))
        .collect::<Vec<_>>()
        .join(",");
    let c = conn.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        c.lock_connect(Arc::new(AppHost { app }), &list, &code)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// جهة الهاتف: البحث عن الكمبيوترات المقفلة على الشبكة نفسها (mDNS، نحو 4 ثوانٍ).
#[tauri::command]
async fn lock_discover() -> Result<Vec<discovery::Found>, String> {
    tauri::async_runtime::spawn_blocking(|| discovery::browse(4))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn lock_phone_disconnect(conn: State<'_, Arc<connection::Conn>>) -> Result<(), String> {
    conn.lock_disconnect();
    Ok(())
}

#[tauri::command]
async fn lock_phone_active(conn: State<'_, Arc<connection::Conn>>) -> Result<bool, String> {
    Ok(conn.lock_client_active())
}

// ---------------- المتجر (المرحلة 8) ----------------

#[tauri::command]
async fn market_config_get(db: State<'_, Db>) -> Result<Option<market::Config>, String> {
    market::config_get(&db)
}

#[tauri::command]
async fn market_config_set(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
    repo: String,
    key: String,
) -> Result<market::Config, String> {
    adm.require()
        .map_err(|_| "ضبط مصدر المتجر من صلاحيات المشرف".to_string())?;
    market::config_set(&db, &repo, &key)
}

#[tauri::command]
async fn market_config_clear(
    adm: State<'_, admin::AdminState>,
    db: State<'_, Db>,
) -> Result<(), String> {
    adm.require()
        .map_err(|_| "ضبط مصدر المتجر من صلاحيات المشرف".to_string())?;
    market::config_clear(&db)
}

#[tauri::command]
async fn market_refresh(app: AppHandle) -> Result<market::MarketView, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db = app.state::<Db>();
        market::refresh(&db, &market::HttpFetcher)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn market_install(
    app: AppHandle,
    id: String,
    version: String,
) -> Result<InstallOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db = app.state::<Db>();
        let dir = app.state::<ToolsDir>();
        market::install(
            &db,
            &dir.0,
            &market::HttpFetcher,
            &id,
            &version,
            env!("CARGO_PKG_VERSION"),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn market_official(db: State<'_, Db>) -> Result<Vec<String>, String> {
    market::official_ids(&db)
}

#[tauri::command]
async fn market_issue_url(
    db: State<'_, Db>,
    kind: String,
    id: String,
    version: String,
) -> Result<String, String> {
    market::issue_url(&db, &kind, &id, &version)
}

#[tauri::command]
async fn studio_check_text(text: String) -> Result<TextCheck, String> {
    Ok(studio::check_text(&text, env!("CARGO_PKG_VERSION")))
}

#[tauri::command]
async fn tool_install_text(
    db: State<'_, Db>,
    tools: State<'_, ToolsDir>,
    text: String,
) -> Result<InstallOutcome, String> {
    studio::install_text(&db, &tools.0, &text, env!("CARGO_PKG_VERSION"))
}

#[tauri::command]
async fn studio_open_tool(
    studio_dir: State<'_, StudioDir>,
    tools: State<'_, ToolsDir>,
    id: String,
) -> Result<ProjectInfo, String> {
    studio::open_tool(&studio_dir.0, &tools.0, &id)
}

#[tauri::command]
async fn studio_runtimes() -> Result<Runtimes, String> {
    tauri::async_runtime::spawn_blocking(studio::runtimes)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    ads::mark_start();
    let app = tauri::Builder::default()
        .manage(TerminalEngine::new())
        .manage(admin::AdminState::default())
        .manage(AdvState::default())
        .manage(WorkflowRuns::default())
        .setup(|app| {
            #[cfg(mobile)]
            app.handle().plugin(tauri_plugin_barcode_scanner::init())?;
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let db = Db::open(&dir.join("terminal-ar.db"))?;
            let _ = db.wf_runs_fail_stale();
            if let Err(e) = plugin::install_builtins(&db, env!("CARGO_PKG_VERSION")) {
                eprintln!("builtin tools registration failed: {e}");
            }
            let tools_dir = dir.join("tools");
            std::fs::create_dir_all(&tools_dir).map_err(|e| e.to_string())?;
            app.manage(ToolsDir(tools_dir));
            let studio_dir = dir.join("studio");
            std::fs::create_dir_all(&studio_dir).map_err(|e| e.to_string())?;
            app.manage(StudioDir(studio_dir));
            let identity = connection::Identity::load_or_create(&dir.join("identity.json"))?;
            app.manage(Arc::new(connection::Conn::new(identity)));
            app.manage(db);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            terminal_open,
            terminal_write,
            terminal_resize,
            terminal_kill,
            terminal_close,
            setting_get,
            setting_set,
            favorites_list,
            favorite_toggle,
            history_add,
            history_recent,
            history_frequent,
            history_clear,
            sessions_recent,
            tools_list,
            tool_install,
            tool_uninstall,
            tool_set_enabled,
            tool_log_add,
            tool_log_recent,
            tool_security,
            tool_set_grants,
            tool_plan_run,
            tool_run_commit,
            tool_rescan,
            trusted_list,
            trusted_add,
            trusted_remove,
            audit_recent,
            conn_status,
            conn_listen,
            conn_pairing,
            conn_pending,
            conn_decide,
            conn_devices,
            conn_unpair,
            conn_catalog,
            conn_allow_get,
            conn_allow_set,
            conn_pair_start,
            conn_pair_confirm,
            conn_remote_list,
            conn_remote_run,
            workflow_list,
            workflow_check,
            workflow_save,
            workflow_delete,
            workflow_plan,
            workflow_grants_set,
            workflow_run,
            workflow_stop,
            workflow_runs,
            admin_probe,
            admin_unlock,
            admin_lock,
            admin_status,
            admin_info,
            admin_open_data_dir,
            admin_rescan_all,
            admin_audit,
            studio_projects,
            studio_create,
            studio_import,
            studio_delete,
            studio_tree,
            studio_read,
            studio_write,
            studio_mkdir,
            studio_delete_path,
            studio_rename,
            studio_validate,
            studio_build,
            studio_test,
            studio_install,
            studio_runtimes,
            studio_format,
            studio_check_text,
            tool_install_text,
            market_config_get,
            market_config_set,
            market_config_clear,
            market_refresh,
            market_install,
            market_issue_url,
            market_official,
            ads_status,
            ads_request,
            lock_info,
            lock_set_enabled,
            lock_begin,
            lock_emergency,
            lock_relock,
            lock_phone_connect,
            lock_discover,
            lock_phone_disconnect,
            lock_phone_active,
            ads_set_enabled,
            studio_open_tool
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Terminal AR");

    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            handle.state::<TerminalEngine>().close_all();
        }
    });
}
