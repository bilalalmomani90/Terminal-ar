// منشئ خطوات مرئي للتدفقات: يقرأ JSON المحرر ويعدّله (إضافة/حذف/ترتيب/تعديل العنوان والأمر والسلوك عند الخطأ)
// دون أن يغيّر أي حقل لا يعرفه (when / parallel / retry …). المحرر النصي يبقى المرجع.
import { h } from "./dom";

interface Step {
  id?: string;
  title?: string;
  run?: string;
  onError?: string;
  parallel?: unknown[];
  [k: string]: unknown;
}
interface Wf {
  steps?: Step[];
  [k: string]: unknown;
}

export const ON_ERROR_LABEL: Record<string, string> = {
  stop: "إيقاف التدفق",
  continue: "المتابعة",
};

export function parseWf(text: string): Wf | null {
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Wf) : null;
  } catch {
    return null;
  }
}

/** معرّف فريد لخطوة جديدة (step1, step2 …) لا يتكرر مع المعرّفات الموجودة بما فيها خطوات التوازي. */
export function nextStepId(wf: Wf): string {
  const used = new Set<string>();
  for (const s of wf.steps ?? []) {
    if (typeof s.id === "string") used.add(s.id);
    for (const p of s.parallel ?? []) {
      const pid = (p as Step).id;
      if (typeof pid === "string") used.add(pid);
    }
  }
  let n = (wf.steps?.length ?? 0) + 1;
  while (used.has(`step${n}`)) n++;
  return `step${n}`;
}

export function addStep(wf: Wf): Wf {
  const steps = [...(wf.steps ?? [])];
  const id = nextStepId(wf);
  steps.push({ id, title: "خطوة جديدة", run: "" });
  return { ...wf, steps };
}

export function removeStep(wf: Wf, i: number): Wf {
  const steps = [...(wf.steps ?? [])];
  steps.splice(i, 1);
  return { ...wf, steps };
}

export function moveStep(wf: Wf, i: number, dir: -1 | 1): Wf {
  const steps = [...(wf.steps ?? [])];
  const j = i + dir;
  if (j < 0 || j >= steps.length) return wf;
  [steps[i], steps[j]] = [steps[j], steps[i]];
  return { ...wf, steps };
}

export function patchStep(wf: Wf, i: number, patch: Partial<Step>): Wf {
  const steps = [...(wf.steps ?? [])];
  const cur = steps[i];
  if (!cur) return wf;
  const next: Step = { ...cur, ...patch };
  // الحقول الفارغة الاختيارية تُحذف بدل أن تبقى نصاً فارغاً
  if (next.onError === "" || next.onError === "stop") delete next.onError;
  steps[i] = next;
  return { ...wf, steps };
}

export function toText(wf: Wf): string {
  return JSON.stringify(wf, null, 2) + "\n";
}

/**
 * يبني اللوحة. `getText` يقرأ نص المحرر الحالي، و`setText` يكتب النص المعدَّل ويطلب فحصاً.
 * تُعاد بناء اللوحة بعد كل تعديل، و`refresh()` تُستدعى عند تغيّر النص من المحرر.
 */
export function createBuilder(getText: () => string, setText: (t: string) => void): { el: HTMLElement; refresh: () => void } {
  const el = h("div", { class: "wf-builder" });

  const apply = (wf: Wf) => {
    setText(toText(wf));
    refresh();
  };

  function refresh(): void {
    el.replaceChildren();
    const wf = parseWf(getText());
    if (!wf) {
      el.append(h("div", { class: "pb-msg", text: "أصلح نص JSON أولاً (انظر الأخطاء أدناه) ثم يعمل المنشئ." }));
      return;
    }
    const steps = wf.steps ?? [];
    if (steps.length === 0) el.append(h("div", { class: "pb-hint", text: "لا توجد خطوات بعد. اضغط «إضافة خطوة»." }));
    steps.forEach((s, i) => {
      const isGroup = Array.isArray(s.parallel);
      const title = h("input", { class: "wfb-input", type: "text", value: s.title ?? "", placeholder: "عنوان الخطوة" });
      title.addEventListener("change", () => apply(patchStep(wf, i, { title: title.value })));
      const row = h(
        "div",
        { class: "wfb-step" },
        h("div", { class: "wfb-head" },
          h("span", { class: "wfb-n", text: String(i + 1) }),
          title,
          h("button", { class: "btn", type: "button", text: "▲", title: "أعلى", disabled: i === 0, onclick: () => apply(moveStep(wf, i, -1)) }),
          h("button", { class: "btn", type: "button", text: "▼", title: "أسفل", disabled: i === steps.length - 1, onclick: () => apply(moveStep(wf, i, 1)) }),
          h("button", { class: "btn danger", type: "button", text: "حذف", onclick: () => apply(removeStep(wf, i)) }),
        ),
      );
      if (isGroup) {
        row.append(h("div", { class: "pb-hint", text: `مجموعة توازي (${s.parallel?.length ?? 0} خطوات) — عدّلها من النص أدناه.` }));
      } else {
        const cmd = h("input", { class: "wfb-input wfb-cmd", type: "text", value: s.run ?? "", placeholder: "الأمر" });
        cmd.dir = "ltr";
        cmd.addEventListener("change", () => apply(patchStep(wf, i, { run: cmd.value })));
        const sel = document.createElement("select");
        sel.className = "wfb-input";
        for (const [v, l] of Object.entries(ON_ERROR_LABEL)) {
          const o = document.createElement("option");
          o.value = v;
          o.textContent = `عند الخطأ: ${l}`;
          sel.append(o);
        }
        sel.value = s.onError === "continue" ? "continue" : "stop";
        sel.addEventListener("change", () => apply(patchStep(wf, i, { onError: sel.value })));
        row.append(cmd, sel);
      }
      el.append(row);
    });
    el.append(h("button", { class: "btn", type: "button", text: "＋ إضافة خطوة", onclick: () => apply(addStep(wf)) }));
  }

  refresh();
  return { el, refresh };
}
