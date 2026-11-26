// المنصة الحالية. يُستنتج من وكيل المتصفح المضمَّن (WebView2 على ويندوز، WKWebView على macOS، WebKitGTK على Linux)
// ليكون متاحاً بشكل متزامن عند تحميل الوحدات. Rust هو المرجع الفعلي (app_info.os).
import { invoke } from "@tauri-apps/api/core";
import type { ShellKind } from "./state";

// ملاحظة: وكيل Android WebView يحوي "Linux" أيضاً، لذلك يُفحص Android قبل Linux.
const ua = typeof navigator === "undefined" ? "" : navigator.userAgent;

export const IS_WINDOWS = /Windows/i.test(ua);
export const IS_MAC = /Macintosh|Mac OS X/i.test(ua);
export const IS_ANDROID = /Android/i.test(ua);
export const OS_NAME: "windows" | "macos" | "android" | "linux" = IS_WINDOWS ? "windows" : IS_MAC ? "macos" : IS_ANDROID ? "android" : "linux";

/** الصدفة الافتراضية للمنصة: PowerShell على ويندوز، وصدفة المستخدم ($SHELL) على غيره. */
export function defaultKind(): ShellKind {
  return IS_WINDOWS ? "powershell" : "default";
}

export function kindLabel(kind: string): string {
  if (kind === "cmd") return "CMD";
  if (kind === "powershell") return "PowerShell";
  return "الصدفة";
}

/**
 * يحوّل صدفة مطلوبة (من أداة أو أمر) إلى صدفة متاحة على هذا النظام، أو null إن لم تتوفر.
 * powershell/cmd لا تعملان على Linux/macOS، وsh لا تعمل على ويندوز: لا نشغّل أمراً بلهجة خاطئة.
 */
export function wantKind(want: string): ShellKind | null {
  if (want === "any") return defaultKind();
  if (want === "powershell" || want === "cmd") return IS_WINDOWS ? want : null;
  if (want === "sh" || want === "default") return IS_WINDOWS ? null : "default";
  return null;
}

export function unsupportedShellMessage(want: string): string {
  return `هذا الإجراء يحتاج صدفة «${want}» وهي غير متاحة على هذا النظام (${OS_NAME}).`;
}

/** معلومات البناء من Rust. play = نسخة Google Play (بلا تنزيل حزم المتجر من الشبكة). */
export const build = { play: false };

export async function loadBuildInfo(): Promise<void> {
  try {
    const i = await invoke<{ play?: boolean }>("app_info");
    build.play = i.play === true;
  } catch {
    /* يبقى الافتراضي */
  }
}
