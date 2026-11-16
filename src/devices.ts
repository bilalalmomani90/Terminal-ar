// الأجهزة والاتصال (المرحلة 7، الدفعة الأولى): اقتران وتشفير على الشبكة المحلية. للمشرف فقط (يفرضه Rust).
import { listen } from "@tauri-apps/api/event";
import { api, type ConnEvent, type ConnStatus, type DeviceRow, type PendingPair } from "./api";
import { confirmDialog, mount, promptDialog, textDialog } from "./dialog";
import { fmtTime, h } from "./dom";
import { setStatus } from "./terminals";

function groups(fp: string): string {
  return fp.replace(/(.{4})/g, "$1 ").trim();
}

async function guard<T>(title: string, fn: () => Promise<T>): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    await textDialog(title, String(err));
    return undefined;
  }
}

export async function openDevices(): Promise<void> {
  let handle: { close: () => void } | null = null;
  let timer: number | undefined;
  const body = h("div", { class: "dev-body" });

  const unlisten = await listen<ConnEvent>("conn-event", (e) => {
    const ev = e.payload;
    if (ev.kind === "pair_sas") {
      void (async () => {
        const ok = await confirmDialog(
          "تأكيد رمز التحقق",
          "يجب أن يظهر هذا الرمز نفسه على الجهاز الآخر. إن اختلف فهناك من يعترض الاتصال: اضغط «إلغاء».",
          ev.text,
        );
        await guard("تعذّر الإرسال", () => api.connPairConfirm(ev.id, ok));
      })();
    } else if (ev.kind === "pair_done") {
      setStatus(`تم الاقتران مع «${ev.text}»`);
      void render();
    } else if (ev.kind === "pair_failed") {
      void textDialog("فشل الاقتران", ev.text);
    } else if (ev.kind === "pair_request" || ev.kind === "pair_closed") {
      void render();
    }
  });

  const close = () => {
    window.clearInterval(timer);
    unlisten();
    handle?.close();
  };

  const section = (title: string, ...kids: (HTMLElement | null)[]) =>
    h("div", { class: "dev-section" }, h("div", { class: "section-title", text: title }), ...kids);

  const render = async () => {
    let st: ConnStatus;
    let pending: PendingPair[];
    let devices: DeviceRow[];
    try {
      [st, pending, devices] = await Promise.all([api.connStatus(), api.connPending(), api.connDevices()]);
    } catch (err) {
      body.replaceChildren(h("div", { class: "muted-box warn", text: String(err) }));
      return;
    }
    body.replaceChildren();

    // هذا الجهاز
    const addr = st.localIp && st.port ? `${st.localIp}:${st.port}` : "";
    body.append(
      section(
        "هذا الجهاز",
        h("div", { class: "row-path", text: `${st.name} — بصمة الهوية: ${groups(st.fingerprint)}` }),
        h("div", {
          class: "dialog-msg",
          text: st.listening
            ? `استقبال الاتصالات يعمل${st.lan ? " على الشبكة المحلية" : " على هذا الجهاز فقط"} — العنوان: ${addr || `المنفذ ${st.port}`}`
            : "استقبال الاتصالات متوقف. لا يستطيع أي جهاز الاتصال بك.",
        }),
        h(
          "div",
          { class: "tool-actions" },
          h("button", {
            class: "btn small " + (st.listening ? "danger" : "primary"),
            text: st.listening ? "إيقاف الاستقبال" : "تفعيل الاستقبال على الشبكة المحلية",
            onclick: () => {
              void (async () => {
                if (!st.listening) {
                  const ok = await confirmDialog(
                    "تفعيل الاستقبال",
                    "سيفتح التطبيق منفذاً على شبكتك المحلية. لا يتصل أحد إلا بعد اقتران توافق عليه أنت، ولا يشغّل إلا ما تسمح به له. سيسألك جدار ويندوز عن السماح. فعّله فقط على شبكة تثق بها.",
                  );
                  if (!ok) return;
                }
                await guard("تعذّر التغيير", () => api.connListen(!st.listening, true));
                await render();
              })();
            },
          }),
          st.listening
            ? h("button", {
                class: "btn small",
                text: st.pairingCode ? "إلغاء وضع الاقتران" : "بدء وضع الاقتران (رمز مؤقت)",
                onclick: () => {
                  void (async () => {
                    await guard("تعذّر البدء", () => api.connPairing(!st.pairingCode));
                    await render();
                  })();
                },
              })
            : null,
        ),
        st.pairingCode
          ? h("div", {
              class: "muted-box",
              text: `رمز الاقتران: ${st.pairingCode}  — صالح ${st.pairingSecsLeft ?? 0} ثانية، ثلاث محاولات خاطئة تُلغيه. أدخله على الجهاز الآخر مع العنوان ${addr}.`,
            })
          : null,
      ),
    );

    // طلبات الاقتران المعلقة
    if (pending.length) {
      body.append(
        section(
          "طلبات اقتران تنتظر قرارك",
          ...pending.map((p) =>
            h(
              "div",
              { class: "tool" },
              h("div", { class: "tool-name", text: `«${p.name}» يطلب الاقتران` }),
              h("div", { class: "row-path", text: `البصمة: ${groups(p.fingerprint)}` }),
              h("div", { class: "dialog-msg", text: `رمز التحقق (يجب أن يطابق ما على الجهاز الآخر): ${p.sas}` }),
              h(
                "div",
                { class: "tool-actions" },
                h("button", {
                  class: "btn small primary",
                  text: "قبول",
                  onclick: () => void guard("تعذّر", () => api.connDecide(p.id, true)).then(render),
                }),
                h("button", {
                  class: "btn small danger",
                  text: "رفض",
                  onclick: () => void guard("تعذّر", () => api.connDecide(p.id, false)).then(render),
                }),
              ),
            ),
          ),
        ),
      );
    }

    // الأجهزة المقترنة
    body.append(
      section(
        `الأجهزة المقترنة (${devices.length})`,
        devices.length === 0 ? h("div", { class: "muted-box", text: "لا أجهزة مقترنة." }) : null,
        ...devices.map((d) => deviceCard(d, render)),
      ),
    );

    // الاقتران كمبادر
    body.append(
      section(
        "الاقتران بجهاز آخر",
        h("div", {
          class: "dialog-msg",
          text: "على الجهاز الآخر: فعّل الاستقبال ثم وضع الاقتران، ثم أدخل هنا عنوانه ورمزه.",
        }),
        h("button", {
          class: "btn small primary",
          text: "اقتران بجهاز",
          onclick: () => {
            void (async () => {
              const a = await promptDialog("اقتران", "عنوان الجهاز (مثل 192.168.1.5 أو 192.168.1.5:47821)", "", true);
              if (!a) return;
              const c = await promptDialog("اقتران", "رمز الاقتران (6 أرقام)", "", true);
              if (!c) return;
              setStatus("جارٍ الاقتران…");
              await guard("تعذّر البدء", () => api.connPairStart(a.trim(), c.trim()));
            })();
          },
        }),
      ),
    );
  };

  const box = h(
    "div",
    { class: "dialog wide wf-dialog" },
    h("div", { class: "dialog-title", text: "الأجهزة والاتصال" }),
    h("div", {
      class: "dialog-msg",
      text: "الدفعة الأولى: اقتران وتشفير على الشبكة المحلية فقط. القناة مشفّرة بين الجهازين، والجهاز المقترن لا يشغّل إلا الأدوات والتدفقات التي تسمح له بها. VPN وRelay غير منفَّذين بعد (انظر docs/CONNECTION.md).",
    }),
    body,
    h("div", { class: "dialog-actions" }, h("button", { class: "btn primary", text: "إغلاق", onclick: close })),
  );
  handle = mount(box, close);
  await render();
  timer = window.setInterval(() => void render(), 2500);
}

function deviceCard(d: DeviceRow, refresh: () => Promise<void>): HTMLElement {
  const isController = d.role === "controller";
  return h(
    "div",
    { class: "tool" },
    h("div", { class: "tool-name", text: d.name }),
    h("div", {
      class: "row-path",
      text: `${isController ? "يتحكم بجهازك" : "يمكنك التحكم به"} — ${groups(d.fingerprint)}${d.lastAddr ? ` — ${d.lastAddr}` : ""}${d.lastSeen ? ` — آخر اتصال ${fmtTime(d.lastSeen)}` : ""}`,
    }),
    h(
      "div",
      { class: "tool-actions" },
      isController
        ? h("button", { class: "btn small", text: "ما يُسمح له بتشغيله", onclick: () => void allowDialog(d) })
        : h("button", { class: "btn small primary", text: "عرض وتشغيل", onclick: () => void remoteDialog(d) }),
      h("button", {
        class: "btn small danger",
        text: "إلغاء الاقتران",
        onclick: () => {
          void (async () => {
            if (!(await confirmDialog("إلغاء الاقتران", `لن يستطيع «${d.name}» الاتصال بعد الآن، وتُحذف صلاحياته.`))) return;
            await guard("تعذّر", () => api.connUnpair(d.fingerprint));
            await refresh();
          })();
        },
      }),
    ),
  );
}

async function allowDialog(d: DeviceRow): Promise<void> {
  const data = await guard("تعذّر التحميل", async () => ({
    catalog: await api.connCatalog(),
    allowed: new Set(await api.connAllowGet(d.fingerprint)),
  }));
  if (!data) return;
  const checks = new Map<string, HTMLInputElement>();
  const list = h("div", { class: "wf-list" });
  if (data.catalog.length === 0) list.append(h("div", { class: "muted-box", text: "لا أدوات ولا تدفقات متاحة." }));
  for (const it of data.catalog) {
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = data.allowed.has(it.item);
    checks.set(it.item, cb);
    list.append(h("label", { class: "dev-check" }, cb, h("span", { text: ` ${it.title}` }), h("span", { class: "row-path", text: ` (${it.item})` })));
  }
  let handle: { close: () => void } | null = null;
  const close = () => handle?.close();
  handle = mount(
    h(
      "div",
      { class: "dialog wide wf-dialog" },
      h("div", { class: "dialog-title", text: `ما يُسمح لـ «${d.name}» بتشغيله` }),
      h("div", {
        class: "dialog-msg",
        text: "التشغيل عن بعد يحترم صلاحيات كل أداة محلياً، ويُرفض الإجراء الذي يحمل نمطاً حساساً أو يطلب تأكيداً أو من نوع insert. لا أوامر حرة ولا طرفية.",
      }),
      list,
      h(
        "div",
        { class: "dialog-actions" },
        h("button", {
          class: "btn primary",
          text: "حفظ",
          onclick: () => {
            void (async () => {
              const items = [...checks.entries()].filter(([, c]) => c.checked).map(([k]) => k);
              await guard("تعذّر الحفظ", () => api.connAllowSet(d.fingerprint, items));
              close();
            })();
          },
        }),
        h("button", { class: "btn", text: "إلغاء", onclick: close }),
      ),
    ),
    close,
  );
}

async function remoteDialog(d: DeviceRow): Promise<void> {
  const items = await guard("تعذّر الاتصال بالجهاز", () => api.connRemoteList(d.fingerprint));
  if (!items) return;
  let handle: { close: () => void } | null = null;
  const close = () => handle?.close();
  const out = h("pre", { class: "adm-out" });
  const list = h("div", { class: "wf-list" });
  if (items.length === 0) list.append(h("div", { class: "muted-box", text: "لم يسمح لك هذا الجهاز بتشغيل أي شيء بعد. اطلب من صاحبه السماح لك." }));
  for (const it of items) {
    list.append(
      h(
        "div",
        { class: "tool" },
        h("div", { class: "tool-name", text: it.title }),
        h("button", {
          class: "btn small primary",
          text: "تشغيل عن بعد",
          onclick: () => {
            void (async () => {
              out.textContent = "جارٍ التشغيل…";
              try {
                const r = await api.connRemoteRun(d.fingerprint, it.item);
                out.textContent = `${r.ok ? "✔" : "✘"} ${r.status}\n\n${r.output}`;
              } catch (err) {
                out.textContent = `تعذّر: ${String(err)}`;
              }
            })();
          },
        }),
      ),
    );
  }
  handle = mount(
    h(
      "div",
      { class: "dialog wide wf-dialog" },
      h("div", { class: "dialog-title", text: `«${d.name}» — ما يمكنك تشغيله` }),
      list,
      out,
      h("div", { class: "dialog-actions" }, h("button", { class: "btn primary", text: "إغلاق", onclick: close })),
    ),
    close,
  );
}
