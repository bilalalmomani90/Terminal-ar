#!/usr/bin/env python3
"""يضيف الجزء الأصلي (Native) إلى مشروع Android المُولَّد وقت البناء (src-tauri/gen/android).

الاستعمال:  android_native.py apply [APP_ID]   |   android_native.py revert
- دائماً: قفل البث المتعدد WifiManager.MulticastLock + صلاحيتا ACCESS_WIFI_STATE وCHANGE_WIFI_MULTICAST_STATE،
          حتى يستقبل أندرويد إعلانات mDNS (اكتشاف الأجهزة). بدونه يتجاهل أندرويد الحزم المتعددة لتوفير البطارية.
- إن مُرّر APP_ID: Start.io (Gradle + meta-data + AD_ID) وجسر JavaScript باسم window.TarAds.
- أي فشل يُرجِع الملفات كما كانت ويكتب NATIVE=0 (البناء يستمر بدون هذه الإضافات).
- revert: يعيد الملفات الأصلية من النسخ الاحتياطية (.tarbak).
معرّف Start.io ليس سرّاً (يظهر في ملف APK نفسه).
"""
import os
import re
import sys
from pathlib import Path

SDK = 'implementation("com.startapp:inapp-sdk:5.3.1")'
ROOT = Path("src-tauri/gen/android/app")


def set_env(v):
    f = os.environ.get("GITHUB_ENV")
    if f:
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(f"NATIVE={v}\n")


def summary(msg):
    f = os.environ.get("GITHUB_STEP_SUMMARY")
    print(msg)
    if f:
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")


def backups():
    return list(ROOT.rglob("*.tarbak"))


def revert():
    n = 0
    for b in backups():
        orig = b.with_suffix("")  # ينزع .tarbak فقط
        orig.write_text(b.read_text(encoding="utf-8"), encoding="utf-8")
        b.unlink()
        n += 1
    # ملف الجسر الإضافي إن وُجد
    for name in ("TarAdsBridge.kt", "TarNet.kt"):
        for extra in ROOT.rglob(name):
            extra.unlink()
    print(f"revert: restored {n} file(s)")


def backup(p: Path):
    b = Path(str(p) + ".tarbak")
    if not b.exists():
        b.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")


def find_one(pattern):
    hits = sorted(ROOT.glob(pattern))
    if not hits:
        raise RuntimeError(f"not found: {pattern}")
    return hits[0]


def patch_main(src: str, app_id: str | None) -> str:
    """يعدّل MainActivity الأصلية بدل استبدالها (فتبقى إعدادات القالب مثل enableEdgeToEdge)."""
    inits = ["TarNet.multicast(this)"]
    if app_id:
        inits.append(f'TarAdsBridge.init(this, "{app_id}")')
    init = "\n    ".join(inits)
    imports = ["import android.os.Bundle"]
    if app_id:
        imports.append("import android.webkit.WebView")
    for imp in imports:
        if imp not in src:
            src = re.sub(r"^(package\s+[\w.]+\s*)$", lambda m: m.group(1) + "\n" + imp, src, count=1, flags=re.M)
    if not re.search(r"class\s+MainActivity\b[^{]*\{", src):
        src = re.sub(r"(class\s+MainActivity\b[^\n{]*)", lambda m: m.group(1) + " {\n}", src, count=1)
    m = re.search(r"override\s+fun\s+onCreate\s*\([^)]*\)\s*\{", src)
    if m:
        src = src[: m.end()] + "\n    " + init + src[m.end():]
    else:
        src = src.rstrip()
        src = src[: src.rfind("}")] + f"  override fun onCreate(savedInstanceState: Bundle?) {{\n    {init}\n    super.onCreate(savedInstanceState)\n  }}\n}}\n"
    if app_id and "onWebViewCreate" not in src:
        src = src.rstrip()
        src = src[: src.rfind("}")] + '  override fun onWebViewCreate(webView: WebView) {\n    webView.addJavascriptInterface(TarAdsBridge(this), "TarAds")\n  }\n}\n'
    return src


def apply(app_id: str | None):
    if app_id is not None and not re.fullmatch(r"\d{6,12}", app_id):
        raise RuntimeError("bad app id")
    gradle = None
    for name in ("build.gradle.kts", "build.gradle"):
        if (ROOT / name).exists():
            gradle = ROOT / name
            break
    if gradle is None:
        raise RuntimeError("app gradle file not found")
    manifest = ROOT / "src/main/AndroidManifest.xml"
    if not manifest.exists():
        raise RuntimeError("manifest not found")
    main = find_one("src/main/java/**/MainActivity.kt")

    for f in (gradle, manifest, main):
        backup(f)

    # 1) Gradle (Start.io فقط)
    g = gradle.read_text(encoding="utf-8")
    if app_id and "com.startapp:inapp-sdk" not in g:
        m = re.search(r"^dependencies\s*\{", g, re.M)
        if not m:
            raise RuntimeError("dependencies block not found")
        line = SDK if gradle.suffix == ".kts" else "implementation 'com.startapp:inapp-sdk:5.3.1'"
        g = g[: m.end()] + "\n    " + line + g[m.end():]
        gradle.write_text(g, encoding="utf-8")

    # 2) Manifest
    x = manifest.read_text(encoding="utf-8")
    if app_id and "com.startapp.sdk.APPLICATION_ID" not in x:
        m = re.search(r"<application\b[^>]*>", x)
        if not m:
            raise RuntimeError("application tag not found")
        meta = f'\n        <meta-data android:name="com.startapp.sdk.APPLICATION_ID" android:value="{app_id}" />'
        x = x[: m.end()] + meta + x[m.end():]
    perms = ["android.permission.ACCESS_WIFI_STATE", "android.permission.CHANGE_WIFI_MULTICAST_STATE"]
    if app_id:
        perms.append("com.google.android.gms.permission.AD_ID")
    for perm in perms:
        if perm not in x:
            m = re.search(r"<manifest\b[^>]*>", x)
            if not m:
                raise RuntimeError("manifest tag not found")
            x = x[: m.end()] + f'\n    <uses-permission android:name="{perm}" />' + x[m.end():]
    manifest.write_text(x, encoding="utf-8")

    # 3) MainActivity + الجسر
    src = main.read_text(encoding="utf-8")
    pm = re.search(r"^package\s+([\w.]+)", src, re.M)
    if not pm:
        raise RuntimeError("package line not found")
    pkg = pm.group(1)
    main.write_text(patch_main(src, app_id), encoding="utf-8")
    (main.parent / "TarNet.kt").write_text(
        f'''package {pkg}

import android.content.Context
import android.net.wifi.WifiManager

/** يمسك قفل البث المتعدد ما دام التطبيق حياً ليستقبل أندرويد إعلانات mDNS (اكتشاف الأجهزة). */
object TarNet {{
  private var lock: WifiManager.MulticastLock? = null

  fun multicast(ctx: Context) {{
    try {{
      val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
      val l = wm.createMulticastLock("terminal-ar-mdns")
      l.setReferenceCounted(false)
      l.acquire()
      lock = l
    }} catch (e: Throwable) {{
    }}
  }}
}}
''',
        encoding="utf-8",
    )
    if not app_id:
        return
    (main.parent / "TarAdsBridge.kt").write_text(
        f'''package {pkg}

import android.app.Activity
import android.webkit.JavascriptInterface
import com.startapp.sdk.adsbase.StartAppAd
import com.startapp.sdk.adsbase.StartAppSDK

/** جسر Start.io: واجهة JavaScript واحدة تعرض إعلاناً بيني (interstitial). القرار بالسماح يأتي من Rust (ads.rs). */
class TarAdsBridge(private val activity: Activity) {{
  companion object {{
    fun init(activity: Activity, appId: String) {{
      try {{
        StartAppSDK.init(activity, appId)
      }} catch (e: Throwable) {{
      }}
    }}
  }}

  @JavascriptInterface
  fun show() {{
    activity.runOnUiThread {{
      try {{
        StartAppAd.showAd(activity)
      }} catch (e: Throwable) {{
      }}
    }}
  }}
}}
''',
        encoding="utf-8",
    )


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: android_native.py apply [APP_ID] | revert")
    cmd = sys.argv[1]
    if cmd == "revert":
        revert()
        set_env(0)
        return
    if cmd == "apply":
        app_id = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
        try:
            apply(app_id)
            set_env(1)
            summary("الإضافات الأصلية: اكتشاف الأجهزة (MulticastLock)" + (f" + إعلانات Start.io (معرّف {app_id})" if app_id else " بلا إعلانات"))
        except Exception as e:  # noqa: BLE001
            revert()
            set_env(0)
            summary(f"الإضافات الأصلية: لم تُدمج ({e}) — البناء يستمر بدونها")
        return
    sys.exit("unknown command")


if __name__ == "__main__":
    main()
