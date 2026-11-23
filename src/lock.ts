// قفل الكمبيوتر بالهاتف.
// - الكمبيوتر: إن فعّل المشرف القفل تظهر شاشة QR فقط حتى يقرأها تطبيق الهاتف. الفتح يبقى ما دامت نبضات الهاتف
//   تصل؛ إذا انقطع الاتصال أو أُغلق التطبيق يعود القفل ويلزم QR جديد. القرار الفعلي في Rust (lock_info/terminal_open).
// - الهاتف (Android): زر «فتح الكمبيوتر» يقرأ QR (أو يُدخل العنوان والرمز يدوياً) ثم يرسل النبضات.
// حدّ صادق: القفل يمنع المستخدم العادي فقط؛ الكود مفتوح فمن عدّل نسخته يتجاوزه.
import { listen } from "@tauri-apps/api/event";
import { api, type ConnEvent, type LockOffer } from "./api";
import { mount, promptDialog, textDialog } from "./dialog";
import { h } from "./dom";
import { IS_ANDROID } from "./platform";
import { maybeShowAd } from "./ads";
import { setStatus } from "./terminals";

// ---------------------------------------------------------------- الكمبيوتر

let screen: HTMLElement | null = null;
let offerAt = 0;
let offer: LockOffer | null = null;
let busy = false;

function svgNode(svg: string): Node | null {
  try {
    const doc = new DOMParser().parseFromString(svg, "image/svg+xml");
    const root = doc.documentElement;
    if (root.nodeName.toLowerCase() !== "svg") return null;
    return document.importNode(root, true);
  } catch {
    return null;
  }
}

async function emergencyForm(): Promise<void> {
  const secret = await promptDialog("مفتاح الطوارئ", "السر", "", true, true);
  if (secret === null) return;
  const name = await promptDialog("مفتاح الطوارئ", "الاسم", "", false, false);
  if (name === null) return;
  const year = await promptDialog("مفتاح الطوارئ", "السنة", "", true, false);
  if (year === null) return;
  try {
    await api.lockEmergency(secret, name, year);
    await tick();
  } catch {
    await textDialog("مفتاح الطوارئ", "بيانات غير صحيحة.");
  }
}

function buildScreen(): HTMLElement {
  const el = h("div", { class: "lock-screen" });
  el.id = "lock-screen";
  return el;
}

function paint(): void {
  if (!screen) return;
  const box = h("div", { class: "lock-box" });
  box.append(h("div", { class: "lock-title", text: "الكمبيوتر مقفل" }));
  box.append(h("div", { class: "lock-sub", text: "افتح تطبيق Terminal AR على هاتفك، واضغط «فتح الكمبيوتر»، ثم امسح هذا الرمز." }));
  if (offer) {
    const qr = h("div", { class: "lock-qr" });
    const n = svgNode(offer.svg);
    if (n) qr.append(n);
    box.append(qr);
    box.append(h("div", { class: "lock-manual", text: "أو أدخل يدوياً على الهاتف:" }));
    const addrs = offer.ip.split(",").map((ip) => `${ip}:${offer?.port}`);
    box.append(h("code", { class: "lock-code", text: `${addrs.join("  ·  ")}   الرمز ${offer.code}` }));
    box.append(
      h("div", {
        class: "lock-note",
        text: "الجهازان على الشبكة نفسها، أو على VPN واحد مثل Tailscale (يُجرَّب كل عنوان بالترتيب). الرمز صالح دقيقتين ويتجدد تلقائياً.",
      }),
    );
  } else {
    box.append(h("div", { class: "lock-note", text: "جارٍ تجهيز الرمز…" }));
  }
  box.append(
    h("button", {
      class: "btn small lock-emerg",
      text: "مفتاح الطوارئ (للمشرف)",
      onclick: () => void emergencyForm(),
    }),
  );
  screen.replaceChildren(box);
}

async function refreshOffer(): Promise<void> {
  try {
    offer = await api.lockBegin();
    offerAt = Date.now();
  } catch (err) {
    offer = null;
    if (screen) {
      screen.replaceChildren(
        h(
          "div",
          { class: "lock-box" },
          h("div", { class: "lock-title", text: "الكمبيوتر مقفل" }),
          h("div", { class: "lock-sub", text: String(err) }),
          h("button", { class: "btn small lock-emerg", text: "مفتاح الطوارئ (للمشرف)", onclick: () => void emergencyForm() }),
        ),
      );
    }
    return;
  }
  paint();
}

async function tick(): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    const info = await api.lockInfo();
    const mustLock = info.supported && info.enabled && !info.status.unlocked;
    if (!mustLock) {
      screen?.remove();
      screen = null;
      offer = null;
      return;
    }
    if (!screen) {
      screen = buildScreen();
      document.body.append(screen);
      paint();
    }
    // الرمز صالح 120 ثانية: نجدده قبل انتهائه بقليل
    if (!offer || Date.now() - offerAt > 90_000) await refreshOffer();
  } catch {
    /* بلا اتصال بـ Rust: لا نغيّر الحالة */
  } finally {
    busy = false;
  }
}

function initDesktopLock(): void {
  void tick();
  window.setInterval(() => void tick(), 1500);
  void listen<ConnEvent>("conn-event", (e) => {
    if (e.payload.kind === "lock_changed") void tick();
  });
}

// ---------------------------------------------------------------- الهاتف

const PRIVATE_IP = /^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/;
// نطاق VPN (Tailscale وأمثاله): 100.64.0.0/10
const VPN_IP = /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/;

export function isLanOrVpnIp(ip: string): boolean {
  return PRIVATE_IP.test(ip) || VPN_IP.test(ip);
}

/** يحلّل «ip:port» أو عدة عناوين مفصولة بفاصلة. يرفض غير الشبكات المحلية وVPN. يرجع نصاً مفصولاً بفواصل. */
export function parseAddrs(text: string): string | null {
  const parts = text.split(",").map((x) => x.trim()).filter((x) => x !== "");
  if (parts.length === 0 || parts.length > 4) return null;
  for (const part of parts) {
    const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(part);
    if (!m) return null;
    const port = Number(m[2]);
    if (!isLanOrVpnIp(m[1]) || port < 1 || port > 65535) return null;
  }
  return parts.join(",");
}

/** يحلّل نص QR: TARLOCK1|ip[,ip...]|port|code. */
export function parsePayload(text: string): { addr: string; code: string } | null {
  const p = text.trim().split("|");
  if (p.length !== 4 || p[0] !== "TARLOCK1") return null;
  const [, ips, port, code] = p;
  if (!/^\d{6}$/.test(code)) return null;
  const addr = parseAddrs(ips.split(",").map((ip) => `${ip.trim()}:${port}`).join(","));
  return addr ? { addr, code } : null;
}

let phoneConnected = false;
let phoneBtn: HTMLButtonElement | null = null;

function paintPhoneBtn(): void {
  if (!phoneBtn) return;
  phoneBtn.textContent = phoneConnected ? "الكمبيوتر متصل ✓" : "فتح الكمبيوتر";
  phoneBtn.classList.toggle("primary", !phoneConnected);
}

async function scanQr(): Promise<string | null> {
  const mod = await import("@tauri-apps/plugin-barcode-scanner");
  let perm = String(await mod.checkPermissions());
  if (perm !== "granted") perm = String(await mod.requestPermissions());
  if (perm !== "granted") throw new Error("لم تُمنح صلاحية الكاميرا. يمكنك إدخال العنوان والرمز يدوياً.");
  const r = await mod.scan({ windowed: false, formats: [mod.Format.QRCode] });
  return r.content ?? null;
}

async function connectWith(addr: string, code: string): Promise<void> {
  const pc = await api.lockPhoneConnect(addr, code);
  phoneConnected = true;
  paintPhoneBtn();
  setStatus(`متصل بالكمبيوتر «${pc}» — أبقِ التطبيق مفتوحاً`);
  void maybeShowAd("pc_unlock"); // فشل الإعلان أو غيابه لا يمنع شيئاً
}

async function phoneDialog(): Promise<void> {
  if (phoneConnected) {
    await api.lockPhoneDisconnect();
    phoneConnected = false;
    paintPhoneBtn();
    setStatus("قُطع الاتصال بالكمبيوتر");
    return;
  }
  let handle: { close: () => void } | null = null;
  const msg = h("div", { class: "dialog-msg", text: "امسح الرمز الظاهر على شاشة الكمبيوتر، أو أدخل العنوان والرمز يدوياً." });
  const addr = h("input", { class: "input", placeholder: "192.168.1.20:47821  (أو عنوان VPN)" });
  addr.setAttribute("dir", "ltr");
  const code = h("input", { class: "input", placeholder: "رمز من 6 أرقام" });
  code.setAttribute("dir", "ltr");
  code.setAttribute("inputmode", "numeric");
  const fail = (e: unknown) => {
    msg.textContent = String(e instanceof Error ? e.message : e);
  };
  const manual = async () => {
    const a = addr.value.trim();
    const c = code.value.trim();
    const list = parseAddrs(a);
    if (!list || !/^\d{6}$/.test(c)) return fail("العنوان أو الرمز غير صحيح (مثال: 192.168.1.20:47821 ثم 6 أرقام).");
    msg.textContent = "جارٍ الاتصال…";
    try {
      await connectWith(list, c);
      handle?.close();
    } catch (e) {
      fail(e);
    }
  };
  const scan = async () => {
    try {
      const text = await scanQr();
      if (!text) return fail("لم يُقرأ شيء.");
      const parsed = parsePayload(text);
      if (!parsed) return fail("هذا ليس رمز قفل Terminal AR (أو ليس على شبكة محلية).");
      msg.textContent = "جارٍ الاتصال…";
      await connectWith(parsed.addr, parsed.code);
      handle?.close();
    } catch (e) {
      fail(e);
    }
  };
  const found = h("div", { class: "pc-found" });
  const discover = async () => {
    msg.textContent = "جارٍ البحث عن الكمبيوترات على الشبكة…";
    found.replaceChildren();
    try {
      const list = await api.lockDiscover();
      if (list.length === 0) {
        msg.textContent = "لم يُعثر على كمبيوتر مقفل على هذه الشبكة. تأكد أنه مقفل وعلى الشبكة نفسها، أو استعمل QR أو العنوان يدوياً (عبر VPN أدخل عنوان VPN).";
        return;
      }
      msg.textContent = "اختر الكمبيوتر ثم أدخل الرمز الظاهر على شاشته:";
      for (const pc of list) {
        found.append(
          h("button", {
            class: "btn",
            text: pc.name,
            onclick: () => {
              addr.value = pc.addrs.join(",");
              code.focus();
            },
          }),
        );
      }
    } catch (e) {
      fail(e);
    }
  };
  const box = h(
    "div",
    { class: "dialog" },
    h("div", { class: "dialog-title", text: "فتح الكمبيوتر" }),
    msg,
    h("button", { class: "btn primary", text: "مسح QR بالكاميرا", onclick: () => void scan() }),
    h("button", { class: "btn", text: "بحث عن الكمبيوترات القريبة", onclick: () => void discover() }),
    found,
    addr,
    code,
    h(
      "div",
      { class: "dialog-actions" },
      h("button", { class: "btn", text: "اتصال يدوي", onclick: () => void manual() }),
      h("button", { class: "btn", text: "إغلاق", onclick: () => handle?.close() }),
    ),
  );
  handle = mount(box, () => handle?.close());
}

function initPhoneLock(): void {
  const actions = document.querySelector(".topbar .actions");
  if (!actions) return;
  phoneBtn = h("button", { class: "btn primary", text: "فتح الكمبيوتر", title: "اقرأ رمز QR من شاشة الكمبيوتر", onclick: () => void phoneDialog() });
  phoneBtn.id = "pc-unlock";
  actions.prepend(phoneBtn);
  void api.lockPhoneActive().then((a) => {
    phoneConnected = a;
    paintPhoneBtn();
  });
  void listen<ConnEvent>("conn-event", (e) => {
    if (e.payload.kind === "lock_lost") {
      phoneConnected = false;
      paintPhoneBtn();
      setStatus(`انقطع الاتصال بالكمبيوتر «${e.payload.text}» — سيُقفل`);
    }
  });
}

export function initLock(): void {
  if (IS_ANDROID) initPhoneLock();
  else initDesktopLock();
}
