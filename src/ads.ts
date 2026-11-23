// الإعلانات (المواصفة 21): هذه الواجهة تطلب *إذناً* من Rust فقط. القرار والعدّاد اليومي في ads.rs.
// الجسر الأصلي (window.TarAds) يضيفه سكربت tools/android_native.py أثناء بناء الـ APK فقط (Start.io).
// إن لم يوجد الجسر لا نطلب إذناً أصلاً، فلا يُحتسب شيء. يُعرض الإعلان فقط إذا كان allow=true، وأي فشل يُتجاهل بصمت.
import { api, type AdsCtx } from "./api";
import { IS_ANDROID } from "./platform";
import { activeSession } from "./terminals";

function terminalFocused(): boolean {
  const s = activeSession();
  if (!s || s.exited) return false;
  return s.host.contains(document.activeElement);
}

interface TarAdsBridge {
  show(): void;
}

function bridge(): TarAdsBridge | null {
  const b = (window as unknown as { TarAds?: TarAdsBridge }).TarAds;
  return b && typeof b.show === "function" ? b : null;
}

/** يُستدعى فقط عند لحظات مناسبة: إكمال مهمة غير حساسة، أو الانتقال إلى قسم لا يخص التنفيذ. */
export async function maybeShowAd(moment: AdsCtx["moment"]): Promise<void> {
  if (!IS_ANDROID) return; // لا إعلانات خارج Android إطلاقاً
  const native = bridge();
  if (!native) return; // لا مزوّد في هذا البناء
  try {
    const ctx: AdsCtx = {
      moment,
      terminalActive: terminalFocused(),
      dialogOpen: document.querySelector(".overlay") !== null,
      commandRunning: false,
      sensitive: false,
    };
    const d = await api.adsRequest(ctx);
    if (!d.allow) return;
    native.show();
  } catch {
    /* فشل الإعلان لا يؤثر على التطبيق أبداً */
  }
}
