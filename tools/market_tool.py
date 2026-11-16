#!/usr/bin/env python3
"""أداة مشرف المتجر (المراجِع): تدير مستودع المتجر الثابت وتوقّع الفهرس والحزم.

الاستخدام:
  python market_tool.py init       --repo-dir DIR --key reviewer.key [--name "اسم المتجر"]
  python market_tool.py add        PKG.tarpkg --repo-dir DIR --key reviewer.key [--notes "ملاحظة المراجعة"]
  python market_tool.py set-status ID VERSION STATUS --repo-dir DIR --key reviewer.key [--notes "السبب"]
  python market_tool.py rating     ID VERSION AVG COUNT --repo-dir DIR --key reviewer.key
  python market_tool.py verify     --repo-dir DIR [--pubkey BASE64]

مفتاح المراجِع: أنشئه بـ  python sign_tarpkg.py keygen --out reviewer.key
  - الملف الخاص سرّي: لا يُرفع إلى GitHub أبداً.
  - المفتاح العام يُعطى لمستخدمي التطبيق عبر قناة موثوقة (لا يُؤخذ من المستودع نفسه).

ما يفعله:
  add         يوقّع الحزمة بمفتاح المراجِع (خطوة «توقيع الحزمة المقبولة»)، ينسخها إلى packages/،
              ويضيف/يحدّث إدخالها في index.json بحالة approved، ثم يزيد seq ويوقّع الفهرس.
  set-status  يغيّر حالة إصدار (suspended/revoked لإيقافه بعد النشر، أو غيرها) ويوقّع الفهرس من جديد.
  الحمولة الموقَّعة للفهرس = "TARPKG-INDEX-V1\\n" + البايتات الخام لملف index.json (ملف index.sig = base64).

هذه الأداة لا تحلّ محل المراجعة البشرية: قرار القبول يبقى لك (انظر docs/MARKETPLACE.md).
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sign_tarpkg as st  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

INDEX_MAGIC = b"TARPKG-INDEX-V1\n"
STATUSES = ["draft", "scanning", "review", "rejected", "approved", "suspended", "revoked"]
KNOWN_PERMS = {
    "system.read", "files.read", "files.write", "files.delete",
    "network", "process.run", "services.manage", "system.sensitive", "elevated",
}
SLUG = re.compile(r"^[a-z][a-z0-9-]*$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
MAX_PKG = 20 * 1024 * 1024


def die(msg):
    sys.exit("خطأ: " + msg)


def index_path(d):
    return os.path.join(d, "index.json")


def load_index(d):
    p = index_path(d)
    if not os.path.exists(p):
        die("لا يوجد index.json — شغّل init أولاً")
    with open(p, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def save_index(d, ix, key):
    """يزيد seq ويحدّث التاريخ ويكتب index.json ثم index.sig."""
    ix["seq"] = int(ix.get("seq", 0)) + 1
    ix["updated"] = datetime.date.today().isoformat()
    ix["packages"].sort(key=lambda e: (e["id"], [int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", e["version"])[:3]]))
    body = (json.dumps(ix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with open(index_path(d), "wb") as f:
        f.write(body)
    sig = key.sign(INDEX_MAGIC + body)
    with open(os.path.join(d, "index.sig"), "w", encoding="ascii") as f:
        f.write(base64.b64encode(sig).decode() + "\n")
    print(f"فهرس رقم {ix['seq']} كُتب ووُقّع ({len(ix['packages'])} إدخال)")


def check_entry(e):
    if not SLUG.match(e["id"]) or len(e["id"]) > 32 or e["id"].endswith("-"):
        die(f"معرّف غير صالح: {e['id']}")
    if not SEMVER.match(e["version"]):
        die(f"إصدار غير صالح: {e['version']}")
    bad = [p for p in e["permissions"] if p not in KNOWN_PERMS]
    if bad:
        die(f"صلاحيات غير معروفة: {bad}")


def cmd_init(a):
    key = st.load_key(a.key)
    d = a.repo_dir
    os.makedirs(os.path.join(d, "packages"), exist_ok=True)
    if os.path.exists(index_path(d)):
        die("index.json موجود بالفعل")
    tpl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "marketplace-template")
    if os.path.isdir(tpl):
        shutil.copytree(tpl, d, dirs_exist_ok=True)
    ix = {"schema": 1, "seq": 0, "updated": "", "name": a.name, "packages": []}
    save_index(d, ix, key)
    pub = base64.b64encode(st.pub_raw(key)).decode()
    print("تم إنشاء المتجر. أعطِ هذا المفتاح العام لمستخدمي التطبيق عبر قناة موثوقة:")
    print(pub)
    print("معرّف المفتاح:", st.key_id(base64.b64decode(pub)))


def cmd_add(a):
    key = st.load_key(a.key)
    d = a.repo_dir
    ix = load_index(d)
    src = a.package
    with zipfile.ZipFile(src) as z:
        try:
            m = json.loads(z.read("manifest.json").decode("utf-8"))
        except KeyError:
            die("الحزمة لا تحتوي manifest.json")
    for f in ("id", "name", "developer", "version"):
        if not m.get(f):
            die(f"manifest ينقصه الحقل {f}")
    e = {
        "id": m["id"],
        "name": m["name"],
        "developer": m["developer"],
        "version": m["version"],
        "description": m.get("description", ""),
        "platforms": m.get("platforms", []),
        "permissions": m.get("permissions", []),
    }
    check_entry(e)
    if any(x["id"] == e["id"] and x["version"] == e["version"] for x in ix["packages"]):
        die("هذا الإصدار موجود في الفهرس بالفعل (لا يُستبدل؛ ارفع رقم الإصدار)")
    out = os.path.join(d, "packages", f"{e['id']}-{e['version']}.tarpkg")
    # توقيع بمفتاح المراجِع (يستبدل أي توقيع سابق للمطوّر)
    sa = argparse.Namespace(input=src, output=out, key=a.key, signer="مراجِع المتجر")
    st.cmd_sign(sa)
    data = open(out, "rb").read()
    if len(data) > MAX_PKG:
        os.remove(out)
        die("الحزمة أكبر من 20MB")
    e["size"] = len(data)
    e["sha256"] = hashlib.sha256(data).hexdigest()
    e["status"] = "approved"
    e["reviewedAt"] = datetime.date.today().isoformat()
    if a.notes:
        e["notes"] = a.notes
    ix["packages"].append(e)
    save_index(d, ix, key)


def cmd_set_status(a):
    if a.status not in STATUSES:
        die(f"الحالة يجب أن تكون إحدى: {', '.join(STATUSES)}")
    key = st.load_key(a.key)
    ix = load_index(a.repo_dir)
    for e in ix["packages"]:
        if e["id"] == a.id and e["version"] == a.version:
            e["status"] = a.status
            if a.notes:
                e["notes"] = a.notes
            if a.status in ("suspended", "revoked") and not e.get("notes"):
                die("اذكر السبب بـ --notes عند الإيقاف أو الإلغاء")
            save_index(a.repo_dir, ix, key)
            print("ملاحظة: يصل التغيير للمستخدمين عند فتحهم المتجر (وقد يتأخر بضع دقائق بسبب ذاكرة GitHub المؤقتة).")
            return
    die("الإصدار غير موجود في الفهرس")


def cmd_rating(a):
    key = st.load_key(a.key)
    ix = load_index(a.repo_dir)
    if not (0 <= a.avg <= 5) or a.count < 0:
        die("تقييم خارج المدى")
    for e in ix["packages"]:
        if e["id"] == a.id and e["version"] == a.version:
            e["rating"] = {"avg": a.avg, "count": a.count}
            save_index(a.repo_dir, ix, key)
            return
    die("الإصدار غير موجود في الفهرس")


def cmd_verify(a):
    d = a.repo_dir
    body = open(index_path(d), "rb").read()
    ix = json.loads(body.decode("utf-8"))
    sig = base64.b64decode(open(os.path.join(d, "index.sig"), "r", encoding="ascii").read().strip())
    if a.pubkey:
        pub = base64.b64decode(a.pubkey)
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, INDEX_MAGIC + body)
        except InvalidSignature:
            die("توقيع الفهرس لا يطابق المفتاح")
        print("توقيع الفهرس صالح")
    else:
        print("تنبيه: لم يُعطَ --pubkey فلم يُتحقق من توقيع الفهرس")
    problems = 0
    seen = set()
    for e in ix["packages"]:
        k = (e["id"], e["version"])
        if k in seen:
            print("مكرر:", k)
            problems += 1
        seen.add(k)
        try:
            check_entry(e)
        except SystemExit as ex:
            print(ex)
            problems += 1
        if e["status"] not in STATUSES:
            print("حالة غير معروفة:", k)
            problems += 1
        p = os.path.join(d, "packages", f"{e['id']}-{e['version']}.tarpkg")
        if e["status"] == "approved" or os.path.exists(p):
            if not os.path.exists(p):
                print("ملف الحزمة مفقود:", p)
                problems += 1
                continue
            data = open(p, "rb").read()
            if hashlib.sha256(data).hexdigest() != e["sha256"] or len(data) != e["size"]:
                print("بصمة/حجم الحزمة لا يطابق الفهرس:", p)
                problems += 1
    if problems:
        sys.exit(f"{problems} مشكلة")
    print("المستودع متّسق")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, key=True):
        p.add_argument("--repo-dir", required=True)
        if key:
            p.add_argument("--key", required=True)

    p = sub.add_parser("init")
    common(p)
    p.add_argument("--name", default="متجر Terminal AR")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("add")
    p.add_argument("package")
    common(p)
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_add)
    p = sub.add_parser("set-status")
    p.add_argument("id")
    p.add_argument("version")
    p.add_argument("status")
    common(p)
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_set_status)
    p = sub.add_parser("rating")
    p.add_argument("id")
    p.add_argument("version")
    p.add_argument("avg", type=float)
    p.add_argument("count", type=int)
    common(p)
    p.set_defaults(fn=cmd_rating)
    p = sub.add_parser("verify")
    common(p, key=False)
    p.add_argument("--pubkey")
    p.set_defaults(fn=cmd_verify)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
