#!/usr/bin/env python3
"""يتحقق من targetSdk في مشروع Android المُولَّد (Google Play يشترط API 36 فما فوق للتطبيقات الجديدة بعد 31 أغسطس 2026).
إن كان أقل يرفعه إلى 36 (مع compileSdk) ويكتب ذلك في ملخص الـ workflow. أي شيء غير مفهوم يُبلَّغ عنه ولا يُخمَّن.
الاستعمال: check_target_sdk.py [مسار build.gradle.kts]
"""
import os
import re
import sys
from pathlib import Path

REQUIRED = 36


def summary(msg: str) -> None:
    print(msg)
    f = os.environ.get("GITHUB_STEP_SUMMARY")
    if f:
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")


def find_gradle(arg):
    if arg:
        return Path(arg)
    for name in ("build.gradle.kts", "build.gradle"):
        p = Path("src-tauri/gen/android/app") / name
        if p.exists():
            return p
    return None


def main() -> int:
    p = find_gradle(sys.argv[1] if len(sys.argv) > 1 else None)
    if p is None or not p.exists():
        summary("targetSdk: لم أجد ملف Gradle — تحقق يدوياً")
        return 0
    s = p.read_text(encoding="utf-8")
    t = re.search(r"targetSdk(?:Version)?\s*=?\s*(\d+)", s)
    c = re.search(r"compileSdk(?:Version)?\s*=?\s*(\d+)", s)
    if not t:
        summary("targetSdk: لم أستطع قراءته من ملف Gradle — تحقق يدوياً قبل الرفع (المطلوب 36 فما فوق)")
        return 0
    target = int(t.group(1))
    if target >= REQUIRED:
        summary(f"targetSdk = {target} ✓ (المطلوب {REQUIRED} فما فوق)")
        return 0
    s = s[: t.start(1)] + str(REQUIRED) + s[t.end(1):]
    c = re.search(r"compileSdk(?:Version)?\s*=?\s*(\d+)", s)
    if c and int(c.group(1)) < REQUIRED:
        s = s[: c.start(1)] + str(REQUIRED) + s[c.end(1):]
    p.write_text(s, encoding="utf-8")
    summary(f"targetSdk كان {target}: رُفع إلى {REQUIRED} (و compileSdk) — تحقق من التشغيل على جهاز بأندرويد 16")
    return 0


if __name__ == "__main__":
    sys.exit(main())
