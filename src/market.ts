// المتجر (المرحلة 8): فهرس ثابت في مستودع GitHub. كل التحقق في Rust (market.rs)؛ هذه الواجهة للعرض فقط.
import { isAdmin } from "./adminState";
import { api, type MarketConfig, type MarketItem, type MarketView } from "./api";
import { confirmDialog, mount, promptDialog, textDialog } from "./dialog";
import { h } from "./dom";
import { permLabel } from "./securityUi";
import { setStatus } from "./terminals";
import { maybeShowAd } from "./ads";
import { afterInstall } from "./toolsPanel";

const STATUS_AR: Record<string, string> = {
  draft: "مسودة",
  scanning: "قيد الفحص",
  review: "قيد المراجعة",
  rejected: "مرفوضة",
  approved: "معتمدة",
  suspended: "موقوفة",
  revoked: "ملغاة",
};

async function guard<T>(title: string, fn: () => Promise<T>): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    await textDialog(title, String(err));
    return undefined;
  }
}

async function showIssueLink(kind: "report" | "rating", it: MarketItem): Promise<void> {
  const url = await guard("تعذّر", () => api.marketIssueUrl(kind, it.id, it.version));
  if (!url) return;
  let copied = false;
  try {
    await navigator.clipboard.writeText(url);
    copied = true;
  } catch {
    /* يبقى الرابط ظاهراً للنسخ اليدوي */
  }
  await textDialog(
    kind === "report" ? "إبلاغ عن أداة" : "تقييم أداة",
    `${copied ? "نُسخ الرابط. " : ""}افتح هذا الرابط في المتصفح لإنشاء ${kind === "report" ? "بلاغ" : "تقييم"} (Issue) في مستودع المتجر على GitHub. لا يرسل التطبيق شيئاً بنفسه، وتحتاج حساب GitHub.\n\n${url}`,
  );
}

function itemCard(it: MarketItem, reload: () => Promise<void>): HTMLElement {
  const stateText: Record<MarketItem["state"], string> = {
    install: "غير مثبّتة",
    update: `مثبّتة ${it.installedVersion ?? ""} — يتوفر تحديث`,
    installed: `مثبّتة ${it.installedVersion ?? ""}`,
    blocked: "محجوبة من المتجر",
    pending: "ليست معتمدة بعد",
  };
  const btns: HTMLElement[] = [];
  if (it.state === "install" || it.state === "update") {
    btns.push(
      h("button", {
        class: "btn small primary",
        text: it.state === "update" ? `تحديث إلى ${it.version}` : "تثبيت",
        onclick: () => {
          void (async () => {
            const perms = it.permissions.length
              ? it.permissions.map(permLabel).join("\n")
              : "لا تطلب أي صلاحية.";
            const ok = await confirmDialog(
              `تثبيت «${it.name}» ${it.version}`,
              `الصلاحيات التي تعلنها الأداة:\n${perms}\n\nوجودها في المتجر لا يمنحها أي صلاحية؛ الموافقة على كل صلاحية منفصلة ويقرّرها المشرف. المراجعة ليست ضماناً مطلقاً للأمان.`,
            );
            if (!ok) return;
            setStatus("جارٍ التنزيل والتحقق…");
            const out = await guard("تعذّر التثبيت", () => api.marketInstall(it.id, it.version));
            if (out) {
              await afterInstall(out);
              await reload();
            }
          })();
        },
      }),
    );
  }
  btns.push(
    h("button", { class: "btn small", text: "إبلاغ", onclick: () => void showIssueLink("report", it) }),
    h("button", { class: "btn small", text: "تقييم", onclick: () => void showIssueLink("rating", it) }),
  );
  const badgeCls = it.status === "approved" ? "official" : it.status === "suspended" || it.status === "revoked" ? "untrusted" : "local";
  return h(
    "div",
    { class: "tool" + (it.state === "blocked" ? " off" : "") },
    h(
      "div",
      { class: "tool-head" },
      h("div", { class: "tool-name", text: it.name }),
      h("span", { class: "badge " + badgeCls, text: STATUS_AR[it.status] ?? it.status }),
      h("span", { class: "ver", text: `v${it.version}` }),
    ),
    it.description ? h("div", { class: "desc show", text: it.description }) : null,
    h("div", {
      class: "row-path",
      text: `${it.developer} — ${stateText[it.state]}${it.official ? " (من المتجر)" : it.installedVersion ? " (محلية)" : ""}${it.reviewedAt ? ` — روجعت ${it.reviewedAt}` : ""}`,
    }),
    h("div", {
      class: "row-path",
      text: it.permissions.length ? `تطلب: ${it.permissions.join("، ")}` : "لا تطلب صلاحيات",
    }),
    it.rating ? h("div", { class: "row-path", text: `التقييم: ${it.rating.avg.toFixed(1)} / 5 (${it.rating.count}) — يحدّثه مشرف المتجر يدوياً` }) : null,
    it.notes ? h("div", { class: "muted-box" + (it.state === "blocked" ? " warn" : ""), text: it.notes }) : null,
    it.blockedVersions.length
      ? h("div", { class: "muted-box warn", text: `إصدارات موقوفة/ملغاة: ${it.blockedVersions.join("، ")}` })
      : null,
    h("div", { class: "tool-actions" }, ...btns),
  );
}

export async function openMarket(): Promise<void> {
  let handle: { close: () => void } | null = null;
  const close = () => {
    handle?.close();
    void maybeShowAd("section_change"); // خروج من قسم لا يخص التنفيذ (Android فقط وبإذن السياسة)
  };
  const body = h("div", { class: "dev-body" });

  const configure = async () => {
    const cur = await api.marketConfigGet().catch(() => null);
    const repo = await promptDialog("مصدر المتجر", "مستودع GitHub بالشكل owner/name", cur?.repo ?? "", true);
    if (!repo) return;
    const key = await promptDialog(
      "مفتاح المراجِع",
      "المفتاح العام (base64) الذي يوقّع الفهرس والحزم. تحصل عليه من مشرف المتجر عبر قناة موثوقة، ولا تنسخه من المستودع نفسه.",
      cur?.key ?? "",
      true,
    );
    if (!key) return;
    await guard("تعذّر الحفظ", () => api.marketConfigSet(repo.trim(), key.trim()));
  };

  const render = async () => {
    body.replaceChildren(h("div", { class: "muted-box", text: "جارٍ التحميل…" }));
    let cfg: MarketConfig | null = null;
    try {
      cfg = await api.marketConfigGet();
    } catch (err) {
      body.replaceChildren(h("div", { class: "muted-box warn", text: String(err) }));
      return;
    }
    const top = h("div", { class: "tool-actions" });
    if (isAdmin()) {
      top.append(
        h("button", {
          class: "btn small",
          text: cfg ? "تغيير المصدر" : "ضبط المصدر",
          onclick: () => void configure().then(render),
        }),
      );
      if (cfg) {
        top.append(
          h("button", {
            class: "btn small danger",
            text: "إزالة المصدر",
            onclick: () => {
              void (async () => {
                if (!(await confirmDialog("إزالة المصدر", "يُسحَب مفتاح المراجِع من الناشرين الموثوقين. الأدوات المثبّتة تبقى."))) return;
                await guard("تعذّر", () => api.marketConfigClear());
                await render();
              })();
            },
          }),
        );
      }
    }
    if (!cfg) {
      body.replaceChildren(
        h("div", {
          class: "muted-box",
          text: isAdmin()
            ? "لم يُضبط مصدر المتجر. اضغط «ضبط المصدر» وأدخل المستودع ومفتاح المراجِع (انظر docs/MARKETPLACE.md لإنشاء المستودع)."
            : "لم يُضبط مصدر المتجر بعد. يضبطه المشرف.",
        }),
        top,
      );
      return;
    }
    let view: MarketView;
    try {
      view = await api.marketRefresh();
    } catch (err) {
      body.replaceChildren(
        h("div", { class: "muted-box warn", text: String(err) }),
        h("div", { class: "row-path", text: `المصدر: ${cfg.repo} — مفتاح المراجِع ${cfg.keyId}` }),
        top,
      );
      return;
    }
    body.replaceChildren(
      h("div", {
        class: "row-path",
        text: `${view.name || "المتجر"} — ${view.repo} — فهرس رقم ${view.seq} (${view.updated}) — مفتاح المراجِع ${view.keyId}`,
      }),
      top,
      ...view.disabled.map((m) => h("div", { class: "muted-box warn", text: m })),
      ...(view.items.length
        ? view.items.map((it) => itemCard(it, render))
        : [h("div", { class: "muted-box", text: "الفهرس فارغ." })]),
    );
    if (view.disabled.length) await import("./state").then((m) => m.refreshTools());
  };

  handle = mount(
    h(
      "div",
      { class: "dialog wide wf-dialog" },
      h("div", { class: "dialog-title", text: "مركز الأدوات" }),
      h("div", {
        class: "dialog-msg",
        text: "أدوات مراجَعة وموقّعة من مراجِع المتجر. تختلف عن الحزم المحلية التي تستوردها للتجربة. وجود أداة هنا لا يمنحها أي صلاحية، والمراجعة ليست ضماناً مطلقاً للأمان. الإصدار الموقوف أو الملغى يُعطَّل تلقائياً عند فتح المتجر أو تحديثه.",
      }),
      body,
      h(
        "div",
        { class: "dialog-actions" },
        h("button", { class: "btn", text: "تحديث", onclick: () => void render() }),
        h("button", { class: "btn primary", text: "إغلاق", onclick: close }),
      ),
    ),
    close,
  );
  await render();
}
