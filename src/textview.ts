// عرض نصي لمخرجات الطرفية.
// الطرفية (xterm.js) تقسّم الشاشة إلى خانات ثابتة ولا تدعم تشكيل العربية رسمياً، فقد تظهر الكلمات العربية
// متقطعة. هذا العرض يأخذ نص الطرفية نفسه ويعرضه كنص عادي يتولى المتصفح تشكيله واتجاهه، مع زر نسخ.
import { invoke } from "@tauri-apps/api/core";
import { api } from "./api";
import { mount } from "./dialog";
import { h } from "./dom";
import { activeSession, setStatus } from "./terminals";

/** نص الطرفية كأسطر (الأسطر الملتفّة تُدمج، والفراغ في النهاية يُحذف). */
export function bufferLines(): string[] | null {
  const s = activeSession();
  if (!s) return null;
  const buf = s.term.buffer.active;
  const lines: string[] = [];
  for (let i = 0; i < buf.length; i++) {
    const line = buf.getLine(i);
    if (!line) continue;
    const text = line.translateToString(true);
    if (line.isWrapped && lines.length > 0) lines[lines.length - 1] += text;
    else lines.push(text);
  }
  while (lines.length > 0 && lines[lines.length - 1].trim() === "") lines.pop();
  return lines;
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** تقرير قصير يُلصق في المحادثة مع المشكلة: النسخة والنظام وحالة القفل وآخر 30 سطراً من الطرفية. بلا أسرار. */
async function buildReport(lines: string[]): Promise<string> {
  const out: string[] = ["تقرير Terminal AR"];
  try {
    const i = await invoke<{ version: string; build: string; os: string }>("app_info");
    out.push(`النسخة: ${i.version} (بناء ${i.build}) — النظام: ${i.os}`);
  } catch {
    out.push("النسخة: غير معروفة");
  }
  out.push(`المتصفح الداخلي: ${navigator.userAgent}`);
  try {
    const l = await api.lockInfo();
    out.push(`القفل: ${l.supported ? (l.enabled ? "مفعّل" : "معطّل") : "غير مدعوم هنا"}${l.status.unlocked ? " (مفتوح)" : ""}`);
  } catch {
    /* تجاهل */
  }
  out.push("--- آخر سطور الطرفية ---");
  out.push(...lines.slice(-30));
  return out.join("\n");
}

function openView(): void {
  const lines = bufferLines();
  if (lines === null) {
    setStatus("لا توجد جلسة طرفية مفتوحة");
    return;
  }
  let handle: { close: () => void } | null = null;
  const body = h("div", { class: "textview" });
  for (const l of lines) {
    // dir=auto: كل سطر يأخذ اتجاهه من أول حرف قوي فيه (عربي ← يمين، إنجليزي ← يسار)
    const row = h("div", { class: "tv-line", text: l === "" ? " " : l });
    row.setAttribute("dir", "auto");
    body.append(row);
  }
  const note = h("div", { class: "dialog-msg", text: "نص الطرفية الحالي بتشكيل المتصفح. يمكنك تحديد النص ونسخه." });
  const box = h(
    "div",
    { class: "dialog textview-dialog" },
    h("div", { class: "dialog-title", text: "عرض نصي" }),
    note,
    body,
    h(
      "div",
      { class: "dialog-actions" },
      h("button", {
        class: "btn primary",
        text: "نسخ الكل",
        onclick: () =>
          void copyText(lines.join("\n")).then((ok) => {
            note.textContent = ok ? "تم النسخ." : "تعذّر النسخ تلقائياً: حدّد النص وانسخه يدوياً.";
          }),
      }),
      h("button", {
        class: "btn",
        text: "نسخ تقرير للمطوّر",
        onclick: () =>
          void buildReport(lines)
            .then((r) => copyText(r))
            .then((ok) => {
              note.textContent = ok ? "نُسخ التقرير: الصقه في المحادثة." : "تعذّر النسخ تلقائياً.";
            }),
      }),
      h("button", { class: "btn", text: "إغلاق", onclick: () => handle?.close() }),
    ),
  );
  handle = mount(box, () => handle?.close());
}

export function initTextView(): void {
  const actions = document.querySelector(".topbar .actions");
  if (!actions) return;
  const btn = h("button", { class: "btn", text: "عرض نصي", title: "عرض مخرجات الطرفية كنص عربي سليم", onclick: openView });
  btn.id = "text-view";
  actions.append(btn);
}
