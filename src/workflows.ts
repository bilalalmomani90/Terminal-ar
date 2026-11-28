// واجهة سير العمل (المرحلة 6): قائمة، محرر JSON مع فحص حي، تشغيل مع متابعة وإيقاف، وسجل.
import { listen } from "@tauri-apps/api/event";
import { isAdmin } from "./adminState";
import { api, type Diag, type WfEvent, type WfPlan, type WfReport, type WfRow, type WfStepResult } from "./api";
import { confirmDialog, mount, textDialog } from "./dialog";
import { fmtTime, h } from "./dom";
import { jsonPathLines, lineForPath } from "./jsonPath";
import { PERM_LABELS } from "./securityUi";
import { createBuilder } from "./wfBuilder";
import { setStatus } from "./terminals";

const STATUS_LABEL: Record<string, string> = {
  pending: "في الانتظار",
  running: "يعمل…",
  ok: "نجحت",
  failed: "فشلت",
  skipped: "تخطّيت",
  cancelled: "أُوقفت",
  partial: "اكتمل مع أخطاء",
};

const STATUS_ICON: Record<string, string> = {
  pending: "○",
  running: "◐",
  ok: "✔",
  failed: "✘",
  skipped: "⤼",
  cancelled: "■",
  partial: "⚠",
};

export const WF_EXAMPLE = `{
  "id": "system-check",
  "name": "فحص سريع للنظام",
  "description": "يقرأ اسم الجهاز، ثم يجمع الأقراص والمنافذ بالتوازي إن نجحت الخطوة الأولى.",
  "variables": { "label": "check" },
  "steps": [
    { "id": "host", "title": "اسم الجهاز", "run": "hostname" },
    {
      "id": "report",
      "title": "الأقراص والمنافذ (بالتوازي)",
      "when": { "step": "host", "exitCode": 0 },
      "parallel": [
        { "id": "disks", "title": "الأقراص", "run": "Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free" },
        { "id": "ports", "title": "المنافذ المفتوحة", "run": "Get-NetTCPConnection -State Listen | Select-Object -First 5 LocalPort,OwningProcess | Format-Table" }
      ]
    },
    {
      "id": "show",
      "title": "عرض نتيجة الخطوة الأولى",
      "run": "Write-Output \\"Host: $env:TAR_STEP_HOST_STDOUT  Label: $env:TAR_VAR_LABEL\\"",
      "onError": "continue"
    }
  ]
}
`;

export function formatReport(r: WfReport): string {
  const lines = [`النتيجة: ${STATUS_LABEL[r.status] ?? r.status}`, ""];
  for (const s of r.steps) {
    lines.push(`${STATUS_ICON[s.status] ?? "?"} ${s.title || s.id} — ${STATUS_LABEL[s.status] ?? s.status}${s.note ? ` (${s.note})` : ""}`);
    if (s.attempts > 1) lines.push(`   المحاولات: ${s.attempts}`);
    if (s.stdout.trim()) lines.push("   " + s.stdout.trim().split("\n").join("\n   "));
    if (s.stderr.trim()) lines.push("   [stderr] " + s.stderr.trim().split("\n").join("\n   "));
    lines.push("");
  }
  return lines.join("\n");
}

function stepCount(body: string): number {
  try {
    const w = JSON.parse(body) as { steps?: { parallel?: unknown[] }[] };
    return (w.steps ?? []).reduce((n, s) => n + 1 + (s.parallel?.length ?? 0), 0);
  } catch {
    return 0;
  }
}

// ---------------- القائمة ----------------

export async function openWorkflows(): Promise<void> {
  let handle: { close: () => void } | null = null;
  const close = () => handle?.close();
  const list = h("div", { class: "wf-list" });

  const render = async () => {
    list.replaceChildren();
    let rows: WfRow[] = [];
    try {
      rows = await api.workflowList();
    } catch (err) {
      list.append(h("div", { class: "muted-box warn", text: `تعذّر التحميل: ${String(err)}` }));
      return;
    }
    if (rows.length === 0) {
      list.append(h("div", { class: "muted-box", text: "لا توجد تدفقات. اضغط «تدفق جديد» لتبدأ من مثال جاهز." }));
    }
    for (const r of rows) {
      list.append(
        h(
          "div",
          { class: "tool" },
          h("div", { class: "tool-name", text: r.name }),
          h("div", { class: "row-path", text: `${r.id} — ${stepCount(r.body)} خطوة — ${fmtTime(r.updatedAt)}` }),
          h(
            "div",
            { class: "tool-actions" },
            h("button", { class: "btn small primary", text: "تشغيل", onclick: () => void runWorkflow(r) }),
            h("button", { class: "btn small", text: "تعديل", onclick: () => void editWorkflow(r.body).then(render) }),
            h("button", { class: "btn small", text: "السجل", onclick: () => void historyDialog(r) }),
            h("button", {
              class: "btn small danger",
              text: "حذف",
              onclick: () => {
                void (async () => {
                  if (!(await confirmDialog("حذف التدفق", `سيُحذف «${r.name}» وسجل تشغيلاته وصلاحياته.`))) return;
                  try {
                    await api.workflowDelete(r.id);
                  } catch (err) {
                    await textDialog("تعذّر الحذف", String(err));
                  }
                  await render();
                })();
              },
            }),
          ),
        ),
      );
    }
  };

  const box = h(
    "div",
    { class: "dialog wide wf-dialog" },
    h("div", { class: "dialog-title", text: "سير العمل" }),
    h("div", {
      class: "dialog-msg",
      text: "تدفقات من خطوات تعمل بالتتابع أو بالتوازي (للقراءة فقط)، مع شروط ومعالجة أخطاء. تمر كل الأوامر بالفحص الأمني نفسه للأدوات، والموافقة على صلاحياتها من المشرف. الأوامر تعمل بصلاحياتك الكاملة ولا يوجد عزل ديناميكي.",
    }),
    list,
    h(
      "div",
      { class: "dialog-actions" },
      h("button", { class: "btn primary", text: "تدفق جديد", onclick: () => void editWorkflow(WF_EXAMPLE).then(render) }),
      h("button", { class: "btn", text: "إغلاق", onclick: close }),
    ),
  );
  handle = mount(box, close);
  await render();
}

// ---------------- المحرر ----------------

function diagLine(d: Diag, lines: Map<string, number>): number {
  return d.line ?? lineForPath(lines, d.path);
}

async function editWorkflow(initial: string): Promise<void> {
  return new Promise<void>((resolve) => {
    let handle: { close: () => void } | null = null;
    const done = () => {
      handle?.close();
      resolve();
    };
    const ta = document.createElement("textarea");
    ta.className = "wf-editor";
    ta.dir = "ltr";
    ta.spellcheck = false;
    ta.value = initial;
    const problems = h("div", { class: "wf-problems" });
    const saveBtn = h("button", { class: "btn primary", text: "حفظ" });
    const fixBtn = h("button", { class: "btn", text: "تطبيق الإصلاح التلقائي" });
    fixBtn.style.display = "none";
    let fixed: string | null = null;
    let timer: number | undefined;
    let seq = 0;

    const goTo = (line: number) => {
      const lines = ta.value.split("\n");
      let pos = 0;
      for (let i = 0; i < Math.min(line - 1, lines.length); i++) pos += lines[i].length + 1;
      ta.focus();
      ta.setSelectionRange(pos, pos + (lines[line - 1]?.length ?? 0));
    };

    const check = async () => {
      const my = ++seq;
      let r;
      try {
        r = await api.workflowCheck(ta.value);
      } catch (err) {
        problems.replaceChildren(h("div", { class: "pb-msg", text: `تعذّر الفحص: ${String(err)}` }));
        return;
      }
      if (my !== seq) return;
      fixed = r.fixed;
      fixBtn.style.display = fixed ? "" : "none";
      problems.replaceChildren();
      const lines = jsonPathLines(fixed ?? ta.value);
      const errs = r.diagnostics.filter((d) => d.severity === "error").length;
      problems.append(
        h("div", {
          class: "pb-head",
          text: r.ok ? "✔ التدفق صالح" + (r.diagnostics.length ? ` (${r.diagnostics.length} تنبيه)` : "") : `✘ ${errs} خطأ — اضغط على خطأ للانتقال إلى مكانه`,
        }),
      );
      for (const d of r.diagnostics) {
        const line = diagLine(d, lines);
        const row = h(
          "div",
          { class: "pb-row " + d.severity },
          h("div", { class: "pb-msg", text: `${d.severity === "error" ? "✘" : "⚠"} السطر ${line}${d.path ? ` (${d.path})` : ""}: ${d.message}` }),
          d.hint ? h("div", { class: "pb-hint", text: `الحل: ${d.hint}` }) : null,
        );
        row.addEventListener("click", () => goTo(line));
        problems.append(row);
      }
      saveBtn.disabled = !r.ok;
    };

    ta.addEventListener("input", () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => void check(), 350);
    });
    fixBtn.addEventListener("click", () => {
      if (fixed) ta.value = fixed;
      void check();
    });
    saveBtn.addEventListener("click", () => {
      void (async () => {
        try {
          const row = await api.workflowSave(fixed ?? ta.value);
          setStatus(`حُفظ التدفق «${row.name}»`);
          done();
        } catch (err) {
          await textDialog("تعذّر الحفظ", String(err));
        }
      })();
    });

    const builder = createBuilder(
      () => ta.value,
      (t) => {
        ta.value = t;
        void check();
      },
    );
    ta.addEventListener("input", () => builder.refresh());
    fixBtn.addEventListener("click", () => builder.refresh());
    const box = h(
      "div",
      { class: "dialog wide wf-dialog" },
      h("div", { class: "dialog-title", text: "تحرير تدفق" }),
      h("div", {
        class: "dialog-msg",
        text: "نتائج الخطوات تصل لأوامرك كمتغيرات بيئة (مثل $env:TAR_STEP_HOST_STDOUT و $env:TAR_VAR_LABEL) ولا تُدرج في نص الأمر، منعاً للحقن.",
      }),
      h("div", { class: "dialog-msg", text: "المنشئ المرئي (يعدّل النص أدناه):" }),
      builder.el,
      ta,
      problems,
      h("div", { class: "dialog-actions" }, saveBtn, fixBtn, h("button", { class: "btn", text: "إلغاء", onclick: done })),
    );
    handle = mount(box, done);
    void check();
  });
}

// ---------------- التشغيل ----------------

function planSummary(p: WfPlan): string {
  const out: string[] = [];
  for (const s of p.steps) {
    out.push(`${s.group ? "  ┣ (توازي) " : "• "}${s.title} — ${s.kind === "run" ? "أمر" : s.kind}`);
    for (const c of s.commands) out.push(`      ${c}`);
  }
  return out.join("\n");
}

async function ensureGrants(p: WfPlan): Promise<boolean> {
  if (p.missing.length === 0) return true;
  const names = p.missing.map((m) => PERM_LABELS[m] ?? m).join("، ");
  if (!isAdmin()) {
    await textDialog("تحتاج موافقة المشرف", `هذا التدفق يحتاج صلاحيات لم تُمنح بعد: ${names}.\nالموافقة عليها من صلاحيات المشرف.`);
    return false;
  }
  const ok = await confirmDialog(
    `منح الصلاحيات للتدفق «${p.name}»`,
    `الأوامر أدناه تحتاج: ${names}.\nراجعها جيداً قبل الموافقة.`,
    planSummary(p),
  );
  if (!ok) return false;
  try {
    await api.workflowGrantsSet(p.id, p.required);
  } catch (err) {
    await textDialog("تعذّر منح الصلاحيات", String(err));
    return false;
  }
  return true;
}

async function runWorkflow(r: WfRow): Promise<void> {
  let plan: WfPlan;
  try {
    plan = await api.workflowPlan(r.id);
  } catch (err) {
    await textDialog("تعذّر تحضير التدفق", String(err));
    return;
  }
  if (!(await ensureGrants(plan))) return;
  const warn = plan.warnings.length ? `\n\nتحذيرات:\n${plan.warnings.join("\n")}` : "";
  if (!(await confirmDialog(`تشغيل «${plan.name}»`, `ستُنفَّذ هذه الخطوات بصلاحياتك:${warn}`, planSummary(plan)))) return;
  await runViewer(r, plan);
}

async function runViewer(r: WfRow, plan: WfPlan): Promise<void> {
  const state = new Map<string, string>();
  const rowEls = new Map<string, { icon: HTMLElement; note: HTMLElement }>();
  const details = h("div", { class: "wf-details" });
  const list = h("div", { class: "wf-steps" });
  for (const s of plan.steps) {
    state.set(s.id, "pending");
    const icon = h("span", { class: "wf-icon", text: STATUS_ICON.pending });
    const note = h("span", { class: "wf-note", text: STATUS_LABEL.pending });
    rowEls.set(s.id, { icon, note });
    list.append(h("div", { class: "wf-step" }, icon, h("span", { class: "wf-title", text: (s.group ? "↳ " : "") + s.title }), note));
  }
  let runId: number | null = null;
  let finished = false;
  let handle: { close: () => void } | null = null;
  const summary = h("div", { class: "dialog-msg", text: "يعمل…" });
  const stopBtn = h("button", { class: "btn danger", text: "إيقاف" });
  const closeBtn = h("button", { class: "btn", text: "إغلاق" });

  const setStep = (id: string, status: string, text = "") => {
    const el = rowEls.get(id);
    if (!el) return;
    el.icon.textContent = STATUS_ICON[status] ?? "?";
    el.note.textContent = (STATUS_LABEL[status] ?? status) + (text ? ` — ${text}` : "");
  };

  const showFinal = async () => {
    finished = true;
    stopBtn.disabled = true;
    try {
      const rows = await api.workflowRuns(r.id, 1);
      const rep = rows[0]?.report ? (JSON.parse(rows[0].report) as WfReport) : null;
      if (rep) {
        summary.textContent = `${STATUS_ICON[rep.status] ?? ""} ${STATUS_LABEL[rep.status] ?? rep.status}`;
        details.replaceChildren();
        for (const s of rep.steps) details.append(stepDetails(s));
        for (const s of rep.steps) setStep(s.id, s.status, s.note);
      }
    } catch (err) {
      summary.textContent = `انتهى، وتعذّر تحميل التقرير: ${String(err)}`;
    }
  };

  // خرج كل خطوة يظهر فور انتهائها؛ التقرير الكامل يستبدله عند نهاية التدفق.
  const liveOutput = (stepId: string, text: string) => {
    const title = plan.steps.find((x) => x.id === stepId)?.title || stepId;
    details.append(h("div", { class: "wf-live" }, h("b", { text: title }), h("pre", { text })));
  };

  const handleEvent = (e: WfEvent) => {
    if (e.kind === "step_start") setStep(e.stepId, "running");
    else if (e.kind === "step_end") setStep(e.stepId, e.status, e.text);
    else if (e.kind === "step_output") liveOutput(e.stepId, e.text);
    else if (e.kind === "run_end") void showFinal();
  };

  const buffer: WfEvent[] = [];
  const unlisten = await listen<WfEvent>("workflow-event", (ev) => {
    if (runId === null) buffer.push(ev.payload);
    else if (ev.payload.runId === runId) handleEvent(ev.payload);
  });

  const close = () => {
    unlisten();
    handle?.close();
  };
  closeBtn.addEventListener("click", () => {
    if (!finished) setStatus("التدفق يعمل في الخلفية؛ تجد نتيجته في «السجل»");
    close();
  });
  stopBtn.addEventListener("click", () => {
    if (runId === null) return;
    stopBtn.disabled = true;
    summary.textContent = "جارٍ الإيقاف…";
    void api.workflowStop(runId).catch((err) => setStatus(`تعذّر الإيقاف: ${String(err)}`));
  });

  const box = h(
    "div",
    { class: "dialog wide wf-dialog" },
    h("div", { class: "dialog-title", text: `تشغيل: ${plan.name}` }),
    summary,
    list,
    details,
    h("div", { class: "dialog-actions" }, stopBtn, closeBtn),
  );
  handle = mount(box, closeBtn.click.bind(closeBtn));

  try {
    runId = await api.workflowRun(r.id);
  } catch (err) {
    summary.textContent = `تعذّر البدء: ${String(err)}`;
    stopBtn.disabled = true;
    unlisten();
    return;
  }
  for (const ev of buffer) if (ev.runId === runId) handleEvent(ev);
}

function stepDetails(s: WfStepResult): HTMLElement {
  const out = [s.stdout.trim(), s.stderr.trim() ? `[stderr]\n${s.stderr.trim()}` : ""].filter(Boolean).join("\n\n");
  const d = h("details", { class: "wf-detail" });
  d.append(h("summary", { text: `${STATUS_ICON[s.status] ?? "?"} ${s.title || s.id} — ${s.durationMs}ms${s.attempts > 1 ? ` — ${s.attempts} محاولات` : ""}` }));
  d.append(h("pre", { class: "adm-out", text: out || "(لا مخرجات)" }));
  return d;
}

// ---------------- السجل ----------------

async function historyDialog(r: WfRow): Promise<void> {
  let rows;
  try {
    rows = await api.workflowRuns(r.id, 30);
  } catch (err) {
    await textDialog("السجل", String(err));
    return;
  }
  if (rows.length === 0) {
    await textDialog(`سجل «${r.name}»`, "لم يُشغَّل هذا التدفق بعد.");
    return;
  }
  let handle: { close: () => void } | null = null;
  const close = () => handle?.close();
  const list = h("div", { class: "wf-list" });
  for (const run of rows) {
    list.append(
      h(
        "div",
        { class: "tool" },
        h("div", { class: "tool-name", text: `${STATUS_ICON[run.status] ?? ""} ${STATUS_LABEL[run.status] ?? run.status}` }),
        h("div", { class: "row-path", text: `${fmtTime(run.startedAt)}${run.finishedAt ? ` — ${run.finishedAt - run.startedAt} ث` : ""}` }),
        run.report
          ? h("button", {
              class: "btn small",
              text: "عرض التقرير",
              onclick: () => void textDialog(`تشغيل ${fmtTime(run.startedAt)}`, formatReport(JSON.parse(run.report ?? "{}") as WfReport)),
            })
          : null,
      ),
    );
  }
  handle = mount(
    h(
      "div",
      { class: "dialog wide wf-dialog" },
      h("div", { class: "dialog-title", text: `سجل «${r.name}»` }),
      list,
      h("div", { class: "dialog-actions" }, h("button", { class: "btn primary", text: "إغلاق", onclick: close })),
    ),
    close,
  );
}
