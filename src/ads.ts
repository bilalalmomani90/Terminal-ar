// الإعلانات (المواصفة 21): هذه الواجهة تطلب *إذناً* من Rust فقط. القرار والعدّاد اليومي في ads.rs.
// في هذا البناء لا يوجد مزوّد إعلانات (لا معرّف Start.io)، فالرد دائماً «غير متاح» ولا يظهر أي إعلان.
// عند إضافة جسر Start.io يُستدعى عرض الإعلان هنا فقط إذا كان allow=true، وأي فشل في العرض يُتجاهل بصمت.
import { api, type AdsCtx } from "./api";
import { IS_ANDROID } from "./platform";
import { activeSession } from "./terminals";

function terminalFocused(): boolean {
  const s = activeSession();
  if (!s || s.exited) return false;
  return s.host.contains(document.activeElement);
}

/** يُستدعى فقط عند لحظات مناسبة: إكمال مهمة غير حساسة، أو الانتقال إلى قسم لا يخص التنفيذ. */
export async function maybeShowAd(moment: AdsCtx["moment"]): Promise<void> {
  if (!IS_ANDROID) return; // لا إعلانات خارج Android إطلاقاً
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
    // هنا يُستدعى جسر Start.io عند إضافته (غير موجود في هذا البناء).
  } catch {
    /* فشل الإعلان لا يؤثر على التطبيق أبداً */
  }
}
