//! Workflow Engine (المرحلة 6): تدفقات من خطوات تُنفَّذ بالتتابع أو بالتوازي، مع شروط ومعالجة أخطاء وإيقاف وسجل.
//!
//! قرارات تصميم مهمة (وصادقة):
//! - لا نستبدل نتائج الخطوات داخل نص الأمر (هذا يفتح باب حقن الأوامر). نتائج الخطوات والمتغيرات
//!   تُمرَّر كمتغيرات بيئة: TAR_VAR_<NAME> و TAR_STEP_<ID>_STDOUT / _EXITCODE / _STATUS
//!   (في PowerShell: $env:TAR_STEP_CHECK_STDOUT).
//! - كل أمر في التدفق يمر بالفحص الساكن نفسه لأوامر الأدوات، ولا يعمل إلا إذا مُنحت صلاحياته للتدفق (المشرف فقط).
//!   خطوات «tool» تمر عبر security::plan_run (البوابة الأصلية للأدوات).
//! - التوازي مسموح فقط لخطوات تحتاج صلاحيات قراءة (system.read / files.read / network).
//! - لا عزل ديناميكي: الأوامر تعمل بصلاحيات المستخدم نفسه (انظر docs/ISOLATION.md).

use crate::plugin::{is_slug, Action, Diag};
use crate::security;
use crate::storage::Db;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_STEPS: usize = 50;
const MAX_TIMEOUT_SEC: u64 = 3600;
const MAX_RETRIES: u32 = 3;
const MAX_VARS: usize = 30;
const ENV_VALUE_CAP: usize = 16_000;
const STDOUT_CAP: usize = 256 * 1024;
const REPORT_STDOUT_CAP: usize = 20_000;
const REPORT_STDERR_CAP: usize = 8_000;
/// صلاحيات يُسمح بها للخطوات المتوازية (قراءة فقط) إضافة إلى process.run.
const PARALLEL_SAFE: [&str; 3] = ["system.read", "files.read", "network"];

fn default_shell() -> String {
    let s = if cfg!(windows) { "powershell" } else { "sh" };
    s.into()
}
fn default_on_error() -> String {
    "stop".into()
}
fn default_timeout() -> u64 {
    120
}

// ---------------------------------------------------------------------------
// النموذج
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cond {
    /// شرط على نتيجة خطوة سابقة
    #[serde(default)]
    pub step: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout_contains: Option<String>,
    #[serde(default)]
    pub stdout_equals: Option<String>,
    /// "ok" | "failed" | "skipped"
    #[serde(default)]
    pub status: Option<String>,
    /// شرط على متغير
    #[serde(default)]
    pub var: Option<String>,
    #[serde(default)]
    pub equals: Option<String>,
    /// يعكس الشرط
    #[serde(default)]
    pub not: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepDef {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default = "default_shell")]
    pub shell: String,
    /// أمر مباشر
    #[serde(default)]
    pub run: Option<String>,
    /// أو إجراء من أداة مثبتة
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub when: Option<Cond>,
    /// "stop" (الافتراضي) | "continue"
    #[serde(default = "default_on_error")]
    pub on_error: String,
    #[serde(default)]
    pub retries: u32,
    #[serde(default = "default_timeout")]
    pub timeout_sec: u64,
    /// مجموعة خطوات تعمل بالتوازي (بدل run/tool)
    #[serde(default)]
    pub parallel: Vec<StepDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    pub steps: Vec<StepDef>,
}

pub fn parse(text: &str) -> Result<Workflow, Diag> {
    serde_json::from_str::<Workflow>(text).map_err(|e| {
        let mut d = Diag::error(
            "",
            format!("JSON غير صالح: {e}"),
            Some("راجع الفواصل والأقواس وأسماء الحقول؛ الحقول غير المعروفة تُرفض حتى لا تضيع أخطاء الكتابة."),
        );
        d.line = Some(e.line());
        d.column = Some(e.column());
        d
    })
}

fn is_var_name(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    s.len() <= 32 && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn perms_of_command(command: &str) -> BTreeSet<String> {
    let action = Action {
        id: "wf".into(),
        title: String::new(),
        description: String::new(),
        shell: "any".into(),
        steps: vec![command.to_string()],
        mode: "run".into(),
        confirm: false,
    };
    security::analyze_steps(&action)
        .into_iter()
        .map(|f| f.permission)
        .collect()
}

fn cond_diags(
    c: &Cond,
    path: &str,
    known: &BTreeSet<String>,
    vars: &BTreeMap<String, String>,
    out: &mut Vec<Diag>,
) {
    let has_step = c.step.is_some();
    let has_var = c.var.is_some();
    if has_step == has_var {
        out.push(Diag::error(
            path,
            "الشرط يجب أن يحدد إما step أو var (واحداً فقط)",
            Some("مثال: {\"step\":\"a\",\"exitCode\":0} أو {\"var\":\"mode\",\"equals\":\"full\"}"),
        ));
        return;
    }
    if let Some(s) = &c.step {
        if !known.contains(s) {
            out.push(Diag::error(
                &format!("{path}.step"),
                format!("الخطوة «{s}» غير معرّفة قبل هذه الخطوة"),
                Some("الشرط يقرأ نتائج خطوات سابقة فقط."),
            ));
        }
        let n = c.exit_code.is_some() as u8
            + c.stdout_contains.is_some() as u8
            + c.stdout_equals.is_some() as u8
            + c.status.is_some() as u8;
        if n != 1 {
            out.push(Diag::error(
                path,
                "حدد شرطاً واحداً على الخطوة: exitCode أو stdoutContains أو stdoutEquals أو status",
                None,
            ));
        }
        if let Some(st) = &c.status {
            if !["ok", "failed", "skipped"].contains(&st.as_str()) {
                out.push(Diag::error(
                    &format!("{path}.status"),
                    "القيم المقبولة: ok أو failed أو skipped",
                    None,
                ));
            }
        }
    }
    if let Some(v) = &c.var {
        if !vars.contains_key(v) {
            out.push(Diag::error(
                &format!("{path}.var"),
                format!("المتغير «{v}» غير معرّف في variables"),
                None,
            ));
        }
        if c.equals.is_none() {
            out.push(Diag::error(path, "شرط المتغير يحتاج equals", None));
        }
    }
}

fn step_diags(
    s: &StepDef,
    path: &str,
    in_group: bool,
    known: &BTreeSet<String>,
    vars: &BTreeMap<String, String>,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<Diag>,
) {
    if !is_slug(&s.id, 32) {
        out.push(Diag::error(
            &format!("{path}.id"),
            format!("معرّف الخطوة «{}» غير صالح", s.id),
            Some("أحرف إنجليزية صغيرة وأرقام وشرطة -، يبدأ بحرف (مثال: check-port)."),
        ));
    } else if !seen.insert(s.id.clone()) {
        out.push(Diag::error(
            &format!("{path}.id"),
            format!("المعرّف «{}» مكرر", s.id),
            None,
        ));
    }
    let kinds = s.run.is_some() as u8 + s.tool.is_some() as u8 + (!s.parallel.is_empty()) as u8;
    if kinds != 1 {
        out.push(Diag::error(
            path,
            "كل خطوة تحتاج واحداً فقط من: run (أمر) أو tool+action (أداة) أو parallel (مجموعة)",
            None,
        ));
    }
    if s.tool.is_some() != s.action.is_some() {
        out.push(Diag::error(
            path,
            "خطوة الأداة تحتاج tool و action معاً",
            None,
        ));
    }
    if in_group && !s.parallel.is_empty() {
        out.push(Diag::error(path, "لا يمكن تداخل مجموعات التوازي", None));
    }
    if !["powershell", "cmd", "sh"].contains(&s.shell.as_str()) {
        out.push(Diag::error(
            &format!("{path}.shell"),
            "القيم المقبولة: powershell أو cmd أو sh",
            None,
        ));
    }
    if !["stop", "continue"].contains(&s.on_error.as_str()) {
        out.push(Diag::error(
            &format!("{path}.onError"),
            "القيم المقبولة: stop أو continue",
            None,
        ));
    }
    if s.retries > MAX_RETRIES {
        out.push(Diag::error(
            &format!("{path}.retries"),
            format!("أقصى عدد من المحاولات الإضافية {MAX_RETRIES}"),
            None,
        ));
    }
    if s.timeout_sec == 0 || s.timeout_sec > MAX_TIMEOUT_SEC {
        out.push(Diag::error(
            &format!("{path}.timeoutSec"),
            format!("المهلة بين 1 و {MAX_TIMEOUT_SEC} ثانية"),
            None,
        ));
    }
    if let Some(r) = &s.run {
        if r.trim().is_empty() {
            out.push(Diag::error(&format!("{path}.run"), "الأمر فارغ", None));
        }
        if in_group {
            let unsafe_perms: Vec<String> = perms_of_command(r)
                .into_iter()
                .filter(|p| !PARALLEL_SAFE.contains(&p.as_str()))
                .collect();
            if !unsafe_perms.is_empty() {
                out.push(Diag::error(
                    &format!("{path}.run"),
                    format!("لا يصلح للتنفيذ المتوازي: يحتاج {}", unsafe_perms.join("، ")),
                    Some("التوازي مسموح لخطوات القراءة فقط. انقل هذه الخطوة خارج parallel."),
                ));
            }
        }
    }
    if let Some(c) = &s.when {
        cond_diags(c, &format!("{path}.when"), known, vars, out);
    }
}

/// فحص ساكن كامل للتدفق مع مسارات الأخطاء.
pub fn diagnose(wf: &Workflow) -> Vec<Diag> {
    let mut out = Vec::new();
    if !is_slug(&wf.id, 32) {
        out.push(Diag::error(
            "id",
            format!("معرّف التدفق «{}» غير صالح", wf.id),
            Some("أحرف إنجليزية صغيرة وأرقام وشرطة -، يبدأ بحرف."),
        ));
    }
    if wf.name.trim().is_empty() || wf.name.chars().count() > 60 {
        out.push(Diag::error("name", "الاسم مطلوب (حتى 60 حرفاً)", None));
    }
    if wf.variables.len() > MAX_VARS {
        out.push(Diag::error(
            "variables",
            format!("أقصى عدد للمتغيرات {MAX_VARS}"),
            None,
        ));
    }
    for k in wf.variables.keys() {
        if !is_var_name(k) {
            out.push(Diag::error(
                &format!("variables.{k}"),
                format!("اسم المتغير «{k}» غير صالح"),
                Some("أحرف إنجليزية وأرقام و_، يبدأ بحرف."),
            ));
        }
    }
    if wf.steps.is_empty() {
        out.push(Diag::error("steps", "لا توجد خطوات", None));
    }
    let total: usize = wf.steps.iter().map(|s| 1 + s.parallel.len()).sum();
    if total > MAX_STEPS {
        out.push(Diag::error(
            "steps",
            format!("أقصى عدد للخطوات {MAX_STEPS}"),
            None,
        ));
    }
    let mut seen = BTreeSet::new();
    let mut known = BTreeSet::new();
    for (i, s) in wf.steps.iter().enumerate() {
        let path = format!("steps[{i}]");
        step_diags(s, &path, false, &known, &wf.variables, &mut seen, &mut out);
        // أبناء المجموعة لا يرون نتائج بعضهم
        for (j, c) in s.parallel.iter().enumerate() {
            let cp = format!("{path}.parallel[{j}]");
            step_diags(c, &cp, true, &known, &wf.variables, &mut seen, &mut out);
        }
        known.insert(s.id.clone());
        for c in &s.parallel {
            known.insert(c.id.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// التحضير (التحليل الأمني وحل خطوات الأدوات)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PStep {
    pub id: String,
    pub title: String,
    /// "run" | "tool:<id>/<action>"
    pub kind: String,
    pub shell: String,
    pub commands: Vec<String>,
    pub cwd: Option<String>,
    pub when: Option<Cond>,
    pub on_error: String,
    pub retries: u32,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum Item {
    Single(PStep),
    Group {
        id: String,
        title: String,
        when: Option<Cond>,
        children: Vec<PStep>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanStep {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub shell: String,
    pub commands: Vec<String>,
    /// معرّف المجموعة المتوازية إن وُجدت
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WfPlan {
    pub id: String,
    pub name: String,
    pub steps: Vec<PlanStep>,
    pub required: Vec<String>,
    pub granted: Vec<String>,
    pub missing: Vec<String>,
    pub warnings: Vec<String>,
}

pub struct Prepared {
    pub items: Vec<Item>,
    pub required: BTreeSet<String>,
    pub warnings: Vec<String>,
}

fn grant_key(wf_id: &str) -> String {
    format!("wf:{wf_id}")
}

fn pstep_from(
    db: &Db,
    tools_dir: &Path,
    s: &StepDef,
    in_group: bool,
    required: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<PStep, String> {
    let timeout = Duration::from_secs(s.timeout_sec.clamp(1, MAX_TIMEOUT_SEC));
    if let Some(cmd) = &s.run {
        let perms = perms_of_command(cmd);
        if in_group {
            if let Some(p) = perms.iter().find(|p| !PARALLEL_SAFE.contains(&p.as_str())) {
                return Err(format!("الخطوة «{}» لا تصلح للتوازي: تحتاج {p}", s.id));
            }
        }
        required.extend(perms);
        return Ok(PStep {
            id: s.id.clone(),
            title: if s.title.is_empty() {
                s.id.clone()
            } else {
                s.title.clone()
            },
            kind: "run".into(),
            shell: s.shell.clone(),
            commands: vec![cmd.clone()],
            cwd: None,
            when: s.when.clone(),
            on_error: s.on_error.clone(),
            retries: s.retries,
            timeout,
        });
    }
    let tool = s.tool.clone().unwrap_or_default();
    let action = s.action.clone().unwrap_or_default();
    // البوابة الأصلية للأدوات: صلاحياتها الممنوحة والفحص الساكن
    let plan = security::plan_run(db, tools_dir, &tool, &action)
        .map_err(|e| format!("الخطوة «{}» (أداة {tool}): {e}", s.id))?;
    if in_group {
        let action_def = Action {
            id: action.clone(),
            title: String::new(),
            description: String::new(),
            shell: plan.shell.clone(),
            steps: plan.steps.clone(),
            mode: "run".into(),
            confirm: false,
        };
        for f in security::analyze_steps(&action_def) {
            if !PARALLEL_SAFE.contains(&f.permission.as_str()) {
                return Err(format!(
                    "الخطوة «{}» لا تصلح للتوازي: أداتها تحتاج {}",
                    s.id, f.permission
                ));
            }
        }
    }
    for w in &plan.warnings {
        warnings.push(format!("{} ({tool}): {w}", s.id));
    }
    let shell = host_shell(&plan.shell);
    Ok(PStep {
        id: s.id.clone(),
        title: if s.title.is_empty() {
            plan.title.clone()
        } else {
            s.title.clone()
        },
        kind: format!("tool:{tool}/{action}"),
        shell: shell.into(),
        commands: plan.steps.clone(),
        cwd: plan.cwd.clone(),
        when: s.when.clone(),
        on_error: s.on_error.clone(),
        retries: s.retries,
        timeout,
    })
}

pub fn prepare(db: &Db, tools_dir: &Path, wf: &Workflow) -> Result<Prepared, String> {
    let diags = diagnose(wf);
    let errs: Vec<String> = diags
        .iter()
        .filter(|d| d.severity == "error")
        .map(|d| format!("{}: {}", d.path, d.message))
        .collect();
    if !errs.is_empty() {
        return Err(errs.join("\n"));
    }
    let mut required: BTreeSet<String> = BTreeSet::new();
    required.insert("process.run".into());
    let mut warnings = Vec::new();
    let mut items = Vec::new();
    for s in &wf.steps {
        if s.parallel.is_empty() {
            items.push(Item::Single(pstep_from(
                db,
                tools_dir,
                s,
                false,
                &mut required,
                &mut warnings,
            )?));
        } else {
            let mut children = Vec::new();
            for c in &s.parallel {
                children.push(pstep_from(
                    db,
                    tools_dir,
                    c,
                    true,
                    &mut required,
                    &mut warnings,
                )?);
            }
            items.push(Item::Group {
                id: s.id.clone(),
                title: if s.title.is_empty() {
                    s.id.clone()
                } else {
                    s.title.clone()
                },
                when: s.when.clone(),
                children,
            });
        }
    }
    Ok(Prepared {
        items,
        required,
        warnings,
    })
}

pub fn plan(db: &Db, tools_dir: &Path, wf: &Workflow) -> Result<WfPlan, String> {
    let p = prepare(db, tools_dir, wf)?;
    let granted: BTreeSet<String> = db.grants_get(&grant_key(&wf.id))?.into_iter().collect();
    let missing: Vec<String> = p.required.difference(&granted).cloned().collect();
    let mut steps = Vec::new();
    for it in &p.items {
        match it {
            Item::Single(s) => steps.push(PlanStep {
                id: s.id.clone(),
                title: s.title.clone(),
                kind: s.kind.clone(),
                shell: s.shell.clone(),
                commands: s.commands.clone(),
                group: None,
            }),
            Item::Group { id, children, .. } => {
                for c in children {
                    steps.push(PlanStep {
                        id: c.id.clone(),
                        title: c.title.clone(),
                        kind: c.kind.clone(),
                        shell: c.shell.clone(),
                        commands: c.commands.clone(),
                        group: Some(id.clone()),
                    });
                }
            }
        }
    }
    Ok(WfPlan {
        id: wf.id.clone(),
        name: wf.name.clone(),
        steps,
        required: p.required.iter().cloned().collect(),
        granted: granted.into_iter().collect(),
        missing,
        warnings: p.warnings,
    })
}

pub fn set_grants(db: &Db, wf_id: &str, perms: &[String]) -> Result<(), String> {
    for p in perms {
        if !crate::plugin::KNOWN_PERMISSIONS.contains(&p.as_str()) {
            return Err(format!("صلاحية غير معروفة: {p}"));
        }
    }
    db.grants_set(&grant_key(wf_id), perms)?;
    db.audit_add("workflow_grants", wf_id, &perms.join(","))
}

pub fn clear_grants(db: &Db, wf_id: &str) -> Result<(), String> {
    db.grants_set(&grant_key(wf_id), &[])
}

// ---------------------------------------------------------------------------
// التنفيذ
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExecReq {
    pub shell: String,
    pub command: String,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct ExecOut {
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
    pub error: Option<String>,
}

pub trait Exec: Send + Sync {
    fn run(&self, req: &ExecReq, cancel: &AtomicBool) -> ExecOut;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepResult {
    pub id: String,
    pub title: String,
    /// "ok" | "failed" | "skipped" | "cancelled"
    pub status: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub attempts: u32,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReport {
    pub workflow_id: String,
    /// "ok" | "partial" | "failed" | "cancelled"
    pub status: String,
    pub steps: Vec<StepResult>,
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…[اقتُطع]")
    }
}

fn env_name(prefix: &str, id: &str, suffix: &str) -> String {
    let up: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{prefix}{up}{suffix}")
}

fn build_env(vars: &BTreeMap<String, String>, results: &[StepResult]) -> Vec<(String, String)> {
    let mut env = Vec::new();
    for (k, v) in vars {
        env.push((env_name("TAR_VAR_", k, ""), trunc(v, ENV_VALUE_CAP)));
    }
    for r in results {
        env.push((
            env_name("TAR_STEP_", &r.id, "_STDOUT"),
            trunc(r.stdout.trim_end(), ENV_VALUE_CAP),
        ));
        env.push((
            env_name("TAR_STEP_", &r.id, "_EXITCODE"),
            r.exit_code.map(|c| c.to_string()).unwrap_or_default(),
        ));
        env.push((env_name("TAR_STEP_", &r.id, "_STATUS"), r.status.clone()));
    }
    env
}

pub fn eval_cond(c: &Cond, vars: &BTreeMap<String, String>, results: &[StepResult]) -> bool {
    let base = if let Some(sid) = &c.step {
        match results.iter().find(|r| &r.id == sid) {
            None => false,
            Some(r) => {
                if let Some(code) = c.exit_code {
                    r.exit_code == Some(code)
                } else if let Some(s) = &c.stdout_contains {
                    r.stdout.contains(s.as_str())
                } else if let Some(s) = &c.stdout_equals {
                    r.stdout.trim() == s.trim()
                } else if let Some(st) = &c.status {
                    &r.status == st
                } else {
                    false
                }
            }
        }
    } else if let Some(v) = &c.var {
        match (vars.get(v), &c.equals) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    } else {
        false
    };
    base != c.not
}

fn skipped(s: &PStep, note: &str) -> StepResult {
    StepResult {
        id: s.id.clone(),
        title: s.title.clone(),
        status: "skipped".into(),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        duration_ms: 0,
        attempts: 0,
        note: note.into(),
    }
}

type Emit<'a> = &'a (dyn Fn(&str, &str, &str, &str) + Sync);

fn run_step(
    s: &PStep,
    exec: &dyn Exec,
    env: Vec<(String, String)>,
    cancel: &AtomicBool,
) -> StepResult {
    let started = Instant::now();
    let mut attempts = 0u32;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit: Option<i32> = None;
    let mut note = String::new();
    let mut status = "failed".to_string();
    'attempts: for _ in 0..=s.retries {
        attempts += 1;
        stdout.clear();
        stderr.clear();
        note.clear();
        let mut all_ok = true;
        for cmd in &s.commands {
            let req = ExecReq {
                shell: s.shell.clone(),
                command: cmd.clone(),
                cwd: s.cwd.clone(),
                env: env.clone(),
                timeout: s.timeout,
            };
            let out = exec.run(&req, cancel);
            stdout.push_str(&out.stdout);
            stderr.push_str(&out.stderr);
            exit = out.exit;
            if out.cancelled {
                status = "cancelled".into();
                note = "أُوقفت بطلب المستخدم".into();
                break 'attempts;
            }
            if let Some(e) = out.error {
                all_ok = false;
                note = format!("تعذّر التشغيل: {e}");
                break;
            }
            if out.timed_out {
                all_ok = false;
                note = format!("انتهت المهلة ({} ثانية)", s.timeout.as_secs());
                break;
            }
            if out.exit != Some(0) {
                all_ok = false;
                note = format!(
                    "رمز الخروج {}",
                    out.exit
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "؟".into())
                );
                break;
            }
        }
        if all_ok {
            status = "ok".into();
            break;
        }
    }
    StepResult {
        id: s.id.clone(),
        title: s.title.clone(),
        status,
        exit_code: exit,
        stdout: trunc(&stdout, REPORT_STDOUT_CAP),
        stderr: trunc(&stderr, REPORT_STDERR_CAP),
        duration_ms: started.elapsed().as_millis() as u64,
        attempts,
        note,
    }
}

pub fn run_prepared(
    wf_id: &str,
    items: &[Item],
    vars: &BTreeMap<String, String>,
    exec: &dyn Exec,
    cancel: &AtomicBool,
    emit: Emit<'_>,
) -> RunReport {
    let mut results: Vec<StepResult> = Vec::new();
    // None = يستمر | Some("failed") | Some("cancelled")
    let mut halted: Option<&'static str> = None;
    let mut any_failed = false;

    for item in items {
        let note_halt = match halted {
            Some("cancelled") => "أُلغي التدفق",
            _ => "أُوقف التدفق بسبب فشل خطوة سابقة",
        };
        if halted.is_none() && cancel.load(Ordering::SeqCst) {
            halted = Some("cancelled");
        }
        match item {
            Item::Single(s) => {
                if halted.is_some() {
                    let r = skipped(s, note_halt);
                    emit("step_end", &s.id, "skipped", &r.note);
                    results.push(r);
                    continue;
                }
                if let Some(c) = &s.when {
                    if !eval_cond(c, vars, &results) {
                        let r = skipped(s, "الشرط غير متحقق");
                        emit("step_end", &s.id, "skipped", &r.note);
                        results.push(r);
                        continue;
                    }
                }
                emit("step_start", &s.id, "running", "");
                let r = run_step(s, exec, build_env(vars, &results), cancel);
                emit("step_end", &s.id, &r.status, &r.note);
                if r.status == "cancelled" {
                    halted = Some("cancelled");
                } else if r.status == "failed" {
                    any_failed = true;
                    if s.on_error != "continue" {
                        halted = Some("failed");
                    }
                }
                results.push(r);
            }
            Item::Group {
                id: gid,
                when,
                children,
                ..
            } => {
                if halted.is_some() {
                    for c in children {
                        let r = skipped(c, note_halt);
                        emit("step_end", &c.id, "skipped", &r.note);
                        results.push(r);
                    }
                    continue;
                }
                if let Some(c) = when {
                    if !eval_cond(c, vars, &results) {
                        for ch in children {
                            let r = skipped(ch, "شرط المجموعة غير متحقق");
                            emit("step_end", &ch.id, "skipped", &r.note);
                            results.push(r);
                        }
                        continue;
                    }
                }
                let env = build_env(vars, &results);
                let _ = gid;
                // قرار التشغيل لكل ابن قبل بدء المجموعة (يرون نتائج ما قبل المجموعة فقط)
                let decisions: Vec<bool> = children
                    .iter()
                    .map(|ch| {
                        ch.when
                            .as_ref()
                            .map(|c| eval_cond(c, vars, &results))
                            .unwrap_or(true)
                    })
                    .collect();
                let group_results: Vec<StepResult> = std::thread::scope(|sc| {
                    let handles: Vec<_> = children
                        .iter()
                        .zip(decisions.iter())
                        .map(|(ch, run)| {
                            if !*run {
                                return None;
                            }
                            let env = env.clone();
                            Some(sc.spawn(move || {
                                emit("step_start", &ch.id, "running", "");
                                let r = run_step(ch, exec, env, cancel);
                                emit("step_end", &ch.id, &r.status, &r.note);
                                r
                            }))
                        })
                        .collect();
                    handles
                        .into_iter()
                        .zip(children.iter())
                        .map(|(h, ch)| match h {
                            None => {
                                let r = skipped(ch, "الشرط غير متحقق");
                                emit("step_end", &ch.id, "skipped", &r.note);
                                r
                            }
                            Some(h) => h.join().unwrap_or_else(|_| {
                                let mut r = skipped(ch, "انهارت الخطوة");
                                r.status = "failed".into();
                                r
                            }),
                        })
                        .collect()
                });
                for (ch, r) in children.iter().zip(group_results.into_iter()) {
                    if r.status == "cancelled" {
                        halted = Some("cancelled");
                    } else if r.status == "failed" {
                        any_failed = true;
                        if ch.on_error != "continue" && halted.is_none() {
                            halted = Some("failed");
                        }
                    }
                    results.push(r);
                }
            }
        }
    }
    let status = match halted {
        Some("cancelled") => "cancelled",
        Some(_) => "failed",
        None if any_failed => "partial",
        None => "ok",
    };
    RunReport {
        workflow_id: wf_id.to_string(),
        status: status.into(),
        steps: results,
    }
}

// ---------------------------------------------------------------------------
// المنفّذ الحقيقي (عمليات النظام)
// ---------------------------------------------------------------------------

pub struct ProcessExec;

/// الصدفة الفعلية لإجراء أداة: cmd تبقى cmd، وما سواها (any/powershell/sh) تصبح صدفة النظام الافتراضية.
pub(crate) fn host_shell(plan_shell: &str) -> &'static str {
    if plan_shell == "cmd" {
        "cmd"
    } else if cfg!(windows) {
        "powershell"
    } else {
        "sh"
    }
}

fn build_command(shell: &str, command: &str) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if shell == "cmd" {
            let mut c = Command::new("cmd");
            c.arg("/C")
                .raw_arg(format!("\"chcp 65001>nul & {command}\""));
            c
        } else {
            let mut c = Command::new("powershell");
            c.args(["-NoProfile", "-NonInteractive", "-Command"])
                .arg(format!(
                    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; {command}"
                ));
            c
        }
    }
    #[cfg(not(windows))]
    {
        match shell {
            // صراحةً طُلبت PowerShell/cmd على نظام يونكس: نشغّلها فقط إن كانت مثبتة (pwsh)، وإلا يظهر خطأ حقيقي.
            "powershell" => {
                let mut c = Command::new("pwsh");
                c.args(["-NoProfile", "-NonInteractive", "-Command", command]);
                c
            }
            "cmd" => Command::new("cmd.exe"),
            _ => {
                let mut c = Command::new("sh");
                c.arg("-c").arg(command);
                c
            }
        }
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    r: Option<R>,
    buf: Arc<Mutex<Vec<u8>>>,
) -> Option<std::thread::JoinHandle<()>> {
    let mut r = r?;
    Some(std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut b) = buf.lock() {
                        let room = STDOUT_CAP.saturating_sub(b.len());
                        b.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        }
    }))
}

fn take_buf(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    buf.lock()
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default()
}

fn wait_reader(h: Option<std::thread::JoinHandle<()>>) {
    if let Some(h) = h {
        // قد تبقي عملية يتيمة الأنبوب مفتوحاً؛ لا ننتظر أكثر من نصف ثانية
        let start = Instant::now();
        while !h.is_finished() && start.elapsed() < Duration::from_millis(500) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if h.is_finished() {
            let _ = h.join();
        }
    }
}

impl Exec for ProcessExec {
    fn run(&self, req: &ExecReq, cancel: &AtomicBool) -> ExecOut {
        let mut cmd = build_command(&req.shell, &req.command);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(d) = &req.cwd {
            cmd.current_dir(d);
        }
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return ExecOut {
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        let out_buf = Arc::new(Mutex::new(Vec::new()));
        let err_buf = Arc::new(Mutex::new(Vec::new()));
        let h1 = spawn_reader(child.stdout.take(), out_buf.clone());
        let h2 = spawn_reader(child.stderr.take(), err_buf.clone());
        let start = Instant::now();
        let mut exit = None;
        let mut timed_out = false;
        let mut cancelled = false;
        loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    exit = st.code();
                    break;
                }
                Ok(None) => {}
                Err(_) => break,
            }
            if cancel.load(Ordering::SeqCst) {
                let _ = child.kill();
                let _ = child.wait();
                cancelled = true;
                break;
            }
            if start.elapsed() > req.timeout {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        wait_reader(h1);
        wait_reader(h2);
        ExecOut {
            exit,
            stdout: take_buf(&out_buf),
            stderr: take_buf(&err_buf),
            timed_out,
            cancelled,
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// اختبارات
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type Handler = Box<dyn Fn(&ExecReq) -> ExecOut + Send + Sync>;

    struct Fake {
        h: Handler,
        calls: Mutex<Vec<ExecReq>>,
    }

    impl Fake {
        fn new(h: Handler) -> Self {
            Fake {
                h,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Exec for Fake {
        fn run(&self, req: &ExecReq, _cancel: &AtomicBool) -> ExecOut {
            self.calls.lock().unwrap().push(req.clone());
            (self.h)(req)
        }
    }

    fn ok(stdout: &str) -> ExecOut {
        ExecOut {
            exit: Some(0),
            stdout: stdout.into(),
            ..Default::default()
        }
    }

    fn fail(code: i32) -> ExecOut {
        ExecOut {
            exit: Some(code),
            ..Default::default()
        }
    }

    fn step(id: &str, cmd: &str) -> PStep {
        PStep {
            id: id.into(),
            title: id.into(),
            kind: "run".into(),
            shell: "powershell".into(),
            commands: vec![cmd.into()],
            cwd: None,
            when: None,
            on_error: "stop".into(),
            retries: 0,
            timeout: Duration::from_secs(5),
        }
    }

    fn noop(_: &str, _: &str, _: &str, _: &str) {}

    fn run(items: Vec<Item>, vars: BTreeMap<String, String>, fake: &Fake) -> RunReport {
        let cancel = AtomicBool::new(false);
        run_prepared("t", &items, &vars, fake, &cancel, &noop)
    }

    fn wf_json(steps: &str) -> String {
        format!(r#"{{"id":"t","name":"اختبار","steps":{steps}}}"#)
    }

    #[test]
    fn parse_rejects_unknown_fields_with_position() {
        let d = parse(r#"{"id":"t","name":"x","steps":[{"id":"a","run":"x","onerror":"stop"}]}"#)
            .unwrap_err();
        assert!(d.message.contains("onerror"), "{}", d.message);
        assert!(d.line.is_some());
    }

    #[test]
    fn diagnose_accepts_a_valid_workflow() {
        let wf = parse(&wf_json(
            r#"[{"id":"a","run":"Get-Date"},{"id":"b","run":"hostname","when":{"step":"a","exitCode":0}}]"#,
        ))
        .unwrap();
        assert!(
            diagnose(&wf).iter().all(|d| d.severity != "error"),
            "{:?}",
            diagnose(&wf)
        );
    }

    #[test]
    fn diagnose_flags_common_mistakes() {
        let wf = parse(&wf_json(
            r#"[
              {"id":"a","run":"x"},
              {"id":"a","run":"y"},
              {"id":"Bad_Id","run":"y"},
              {"id":"c"},
              {"id":"d","run":"z","when":{"step":"later","exitCode":0}},
              {"id":"later","run":"z"},
              {"id":"e","run":"z","onError":"ignore","timeoutSec":0,"retries":9}
            ]"#,
        ))
        .unwrap();
        let msgs: Vec<String> = diagnose(&wf)
            .into_iter()
            .map(|d| format!("{}|{}", d.path, d.message))
            .collect();
        let all = msgs.join("\n");
        assert!(all.contains("مكرر"), "{all}");
        assert!(all.contains("غير صالح"), "{all}");
        assert!(all.contains("واحداً فقط من"), "{all}");
        assert!(all.contains("غير معرّفة قبل"), "{all}");
        assert!(all.contains("stop أو continue"), "{all}");
        assert!(all.contains("المهلة"), "{all}");
        assert!(all.contains("المحاولات"), "{all}");
    }

    #[test]
    fn parallel_group_rejects_write_commands() {
        let wf = parse(&wf_json(
            r#"[{"id":"g","parallel":[
                {"id":"r","run":"Get-Process"},
                {"id":"w","run":"Remove-Item C:\\temp\\x -Recurse"}
            ]}]"#,
        ))
        .unwrap();
        let all: String = diagnose(&wf)
            .into_iter()
            .map(|d| d.message)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("لا يصلح للتنفيذ المتوازي"), "{all}");
    }

    #[test]
    fn results_are_passed_as_env_not_in_command_text() {
        let fake = Fake::new(Box::new(|req| {
            if req.command == "first" {
                ok("hello; rm -rf /\n")
            } else {
                ok("")
            }
        }));
        let mut vars = BTreeMap::new();
        vars.insert("port".to_string(), "3000".to_string());
        let rep = run(
            vec![
                Item::Single(step("check-a", "first")),
                Item::Single(step("b", "second")),
            ],
            vars,
            &fake,
        );
        assert_eq!(rep.status, "ok");
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[1].command, "second");
        let env: BTreeMap<_, _> = calls[1].env.iter().cloned().collect();
        assert_eq!(
            env.get("TAR_STEP_CHECK_A_STDOUT").unwrap(),
            "hello; rm -rf /"
        );
        assert_eq!(env.get("TAR_STEP_CHECK_A_EXITCODE").unwrap(), "0");
        assert_eq!(env.get("TAR_STEP_CHECK_A_STATUS").unwrap(), "ok");
        assert_eq!(env.get("TAR_VAR_PORT").unwrap(), "3000");
    }

    #[test]
    fn conditions_skip_steps() {
        let fake = Fake::new(Box::new(|req| {
            if req.command == "a" {
                ok("READY")
            } else {
                ok("")
            }
        }));
        let mut b = step("b", "b");
        b.when = Some(Cond {
            step: Some("a".into()),
            stdout_contains: Some("READY".into()),
            ..Default::default()
        });
        let mut c = step("c", "c");
        c.when = Some(Cond {
            step: Some("a".into()),
            stdout_contains: Some("READY".into()),
            not: true,
            ..Default::default()
        });
        let rep = run(
            vec![
                Item::Single(step("a", "a")),
                Item::Single(b),
                Item::Single(c),
            ],
            BTreeMap::new(),
            &fake,
        );
        let st: Vec<&str> = rep.steps.iter().map(|r| r.status.as_str()).collect();
        assert_eq!(st, vec!["ok", "ok", "skipped"]);
    }

    #[test]
    fn variable_conditions_work() {
        let fake = Fake::new(Box::new(|_| ok("")));
        let mut vars = BTreeMap::new();
        vars.insert("mode".to_string(), "full".to_string());
        let mut s = step("a", "a");
        s.when = Some(Cond {
            var: Some("mode".into()),
            equals: Some("quick".into()),
            ..Default::default()
        });
        let rep = run(vec![Item::Single(s)], vars, &fake);
        assert_eq!(rep.steps[0].status, "skipped");
    }

    #[test]
    fn failure_stops_by_default_and_continue_keeps_going() {
        let fake = Fake::new(Box::new(|req| {
            if req.command == "bad" {
                fail(3)
            } else {
                ok("")
            }
        }));
        let rep = run(
            vec![
                Item::Single(step("a", "bad")),
                Item::Single(step("b", "good")),
            ],
            BTreeMap::new(),
            &fake,
        );
        assert_eq!(rep.status, "failed");
        assert_eq!(rep.steps[0].status, "failed");
        assert_eq!(rep.steps[0].exit_code, Some(3));
        assert_eq!(rep.steps[1].status, "skipped");

        let mut a = step("a", "bad");
        a.on_error = "continue".into();
        let rep = run(
            vec![Item::Single(a), Item::Single(step("b", "good"))],
            BTreeMap::new(),
            &fake,
        );
        assert_eq!(rep.status, "partial");
        assert_eq!(rep.steps[1].status, "ok");
    }

    #[test]
    fn retries_until_success() {
        let n = Arc::new(Mutex::new(0));
        let n2 = n.clone();
        let fake = Fake::new(Box::new(move |_| {
            let mut c = n2.lock().unwrap();
            *c += 1;
            if *c < 3 {
                fail(1)
            } else {
                ok("done")
            }
        }));
        let mut a = step("a", "flaky");
        a.retries = 3;
        let rep = run(vec![Item::Single(a)], BTreeMap::new(), &fake);
        assert_eq!(rep.status, "ok");
        assert_eq!(rep.steps[0].attempts, 3);
    }

    #[test]
    fn timeout_and_spawn_errors_are_failures() {
        let fake = Fake::new(Box::new(|req| {
            if req.command == "slow" {
                ExecOut {
                    timed_out: true,
                    ..Default::default()
                }
            } else {
                ExecOut {
                    error: Some("not found".into()),
                    ..Default::default()
                }
            }
        }));
        let mut a = step("a", "slow");
        a.on_error = "continue".into();
        let rep = run(
            vec![Item::Single(a), Item::Single(step("b", "missing"))],
            BTreeMap::new(),
            &fake,
        );
        assert!(rep.steps[0].note.contains("المهلة"));
        assert!(rep.steps[1].note.contains("not found"));
        assert_eq!(rep.steps[1].status, "failed");
    }

    #[test]
    fn cancel_stops_remaining_steps() {
        let fake = Fake::new(Box::new(|_| ExecOut {
            cancelled: true,
            ..Default::default()
        }));
        let rep = run(
            vec![Item::Single(step("a", "x")), Item::Single(step("b", "y"))],
            BTreeMap::new(),
            &fake,
        );
        assert_eq!(rep.status, "cancelled");
        assert_eq!(rep.steps[0].status, "cancelled");
        assert_eq!(rep.steps[1].status, "skipped");
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn parallel_group_runs_all_children_and_keeps_order() {
        let fake = Fake::new(Box::new(|req| ok(&req.command)));
        let item = Item::Group {
            id: "g".into(),
            title: "g".into(),
            when: None,
            children: vec![step("p1", "one"), step("p2", "two"), step("p3", "three")],
        };
        let rep = run(
            vec![item, Item::Single(step("after", "x"))],
            BTreeMap::new(),
            &fake,
        );
        let ids: Vec<&str> = rep.steps.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["p1", "p2", "p3", "after"]);
        assert_eq!(rep.steps[1].stdout, "two");
        assert_eq!(rep.status, "ok");
    }

    #[test]
    fn group_child_failure_stops_following_items() {
        let fake = Fake::new(Box::new(|req| {
            if req.command == "bad" {
                fail(1)
            } else {
                ok("")
            }
        }));
        let item = Item::Group {
            id: "g".into(),
            title: "g".into(),
            when: None,
            children: vec![step("p1", "bad"), step("p2", "fine")],
        };
        let rep = run(
            vec![item, Item::Single(step("after", "x"))],
            BTreeMap::new(),
            &fake,
        );
        assert_eq!(rep.status, "failed");
        assert_eq!(rep.steps[1].status, "ok");
        assert_eq!(rep.steps[2].status, "skipped");
    }

    #[test]
    fn env_values_are_truncated() {
        let big = "x".repeat(ENV_VALUE_CAP + 500);
        let r = StepResult {
            id: "a-b".into(),
            title: String::new(),
            status: "ok".into(),
            exit_code: Some(0),
            stdout: big,
            stderr: String::new(),
            duration_ms: 0,
            attempts: 1,
            note: String::new(),
        };
        let env = build_env(&BTreeMap::new(), &[r]);
        let v = &env
            .iter()
            .find(|(k, _)| k == "TAR_STEP_A_B_STDOUT")
            .unwrap()
            .1;
        assert!(v.chars().count() <= ENV_VALUE_CAP + 20);
        assert!(v.contains("اقتُطع"));
    }

    #[cfg(windows)]
    #[test]
    fn real_process_captures_output_env_and_timeout() {
        let exec = ProcessExec;
        let cancel = AtomicBool::new(false);
        let req = ExecReq {
            shell: "cmd".into(),
            command: "echo hello %TAR_VAR_X%".into(),
            cwd: None,
            env: vec![("TAR_VAR_X".into(), "world".into())],
            timeout: Duration::from_secs(20),
        };
        let out = exec.run(&req, &cancel);
        assert_eq!(out.exit, Some(0), "{:?}", out);
        assert!(out.stdout.contains("hello world"), "{:?}", out);

        let slow = ExecReq {
            shell: "cmd".into(),
            command: "ping -n 10 127.0.0.1".into(),
            cwd: None,
            env: vec![],
            timeout: Duration::from_millis(700),
        };
        let out = exec.run(&slow, &cancel);
        assert!(out.timed_out, "{:?}", out);

        let bad = ExecReq {
            shell: "cmd".into(),
            command: "exit 7".into(),
            cwd: None,
            env: vec![],
            timeout: Duration::from_secs(20),
        };
        assert_eq!(exec.run(&bad, &cancel).exit, Some(7));
    }
}
