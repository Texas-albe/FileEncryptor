#!/usr/bin/env python3
# Android 发布包离线校验：签名 / 版本号 / native 库 / 资源形态
# 用法：
#   python scripts/verify_android_release.py
#   python scripts/verify_android_release.py --apk PATH --expect-version 1.0.0 --expect-code 7
import argparse
import hashlib
import os
import re
import subprocess
import sys
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID_SDK = r"E:/Microsoft Visual Studio SDK/Android/android-sdk"
JAVA_SDK = r"E:/Microsoft Visual Studio SDK/Android/openjdk/jdk-21.0.8"
BT = os.path.join(ANDROID_SDK, "build-tools", "36.0.0")
APKSIGNER = os.path.join(BT, "apksigner.bat")
AAPT2 = os.path.join(BT, "aapt2.exe")
DEFAULT_APK = r"E:/Release/android/com.yaoyingluo.fileencryptor-Signed.apk"
DEFAULT_NATIVE = os.path.join(REPO, "GUI-Android", "Platforms", "Android", "native", "arm64-v8a", "libvdisk.so")

results = []


def chk(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + detail) if detail else ""))


def md5(data):
    return hashlib.md5(data).hexdigest()


def run(cmd, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", default=DEFAULT_APK)
    ap.add_argument("--native-so", default=DEFAULT_NATIVE)
    ap.add_argument("--expect-version", default="1.0.0")
    ap.add_argument("--expect-code", type=int, default=7)
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        chk("APK 存在", False, args.apk)
        return 1
    size = os.path.getsize(args.apk)
    chk("APK 存在", True, "%d B  md5 %s" % (size, md5(open(args.apk, "rb").read())))

    with zipfile.ZipFile(args.apk) as z:
        names = z.namelist()
        chk("ZIP 条目", len(names) >= 1552, "%d 条（基线 1552）" % len(names))
        vdisk_path = "lib/arm64-v8a/libvdisk.so"
        chk("libvdisk.so 在包内", vdisk_path in names)
        if vdisk_path in names:
            apk_md5 = md5(z.read(vdisk_path))
            if os.path.isfile(args.native_so):
                src_md5 = md5(open(args.native_so, "rb").read())
                chk("libvdisk.so 与工程一致", apk_md5 == src_md5, "%s / %s" % (apk_md5, src_md5))
            else:
                chk("libvdisk.so 与工程一致", False, "工程侧 native so 不存在")
        has_store = "lib/arm64-v8a/libassembly-store.so" in names
        has_aot = any(n.startswith("lib/arm64-v8a/libaot-") and n.endswith(".dll.so") for n in names)
        has_asm = any(n.startswith("assemblies/") and n.endswith(".dll") for n in names)
        chk("托管程序集形态", has_store and (has_aot or has_asm),
            "store=%s aot=%s assemblies=%s" % (has_store, has_aot, has_asm))

    if os.path.isfile(APKSIGNER):
        r = run([APKSIGNER, "verify", "--verbose", args.apk], {"JAVA_HOME": JAVA_SDK})
        out = (r.stdout or "") + (r.stderr or "")
        ok = r.returncode == 0 and "Verifies" in out
        v2 = re.search(r"Verified using v2 scheme.*:\s*true", out) is not None
        v3 = re.search(r"Verified using v3 scheme \(APK Signature Scheme v3\):\s*true", out) is not None
        chk("apksigner v2+v3", ok and v2 and v3,
            "rc=%d v2=%s v3=%s signers=%s" % (
                r.returncode, v2, v3,
                (re.search(r"Number of signers: ([0-9]+)", out).group(1) if re.search(r"Number of signers: ([0-9]+)", out) else "?")))
        if not ok:
            print(out[-1200:])
    else:
        chk("apksigner v2+v3", False, "找不到 " + APKSIGNER)

    if os.path.isfile(AAPT2):
        r = run([AAPT2, "dump", "badging", args.apk])
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"versionName='([^']*)'", out)
        c = re.search(r"versionCode='([^']*)'", out)
        ver = m.group(1) if m else ""
        code = c.group(1) if c else ""
        chk("versionName", ver == args.expect_version, "%s (期望 %s)" % (ver or "?", args.expect_version))
        chk("versionCode", code == str(args.expect_code), "%s (期望 %d)" % (code or "?", args.expect_code))
    else:
        chk("versionName/versionCode", False, "找不到 " + AAPT2)

    bad = [n for n, ok, _ in results if not ok]
    print("\n%d 项通过 / %d 项失败" % (len(results) - len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    for s in (sys.stdout, sys.stderr):
        if s is not None:
            try:
                s.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    sys.exit(main())
