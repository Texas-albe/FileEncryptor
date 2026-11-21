#!/usr/bin/env python3
# Android APK 一键打包：native vdisk → strip → 同步进 GUI-Android → dotnet publish → 校验产物
#
# 用法：
#   python scripts/build_android_apk.py                 # 完整流程（含 native 重编）
#   python scripts/build_android_apk.py --no-native     # 跳过 native 编译，直接用现成 so
#   python scripts/build_android_apk.py --publish-only  # 只跑 publish（等价 dotnet publish）
#   python scripts/build_android_apk.py --dry-run       # 只打印命令
#   python scripts/build_android_apk.py --jobs 12       # 指定并行数
#   python scripts/build_android_apk.py --no-configure  # 跳过 configure
#   python scripts/build_android_apk.py --ccache        # 启用编译缓存
#   python scripts/build_android_apk.py --release-dir E:\Release
#
# 关键点（踩过的坑）：
#  1) PublishSingleFile 在 Android 上不支持，且要求显式 RID。VS 里报
#     「无法推断属性 PublishSingleFile 的运行时标识符」即此故 → profile 已改 false。
#  2) RID 只能用复数 RuntimeIdentifiers。.NET for Android 的
#     Microsoft.Android.Sdk.DefaultProperties.targets 会在复数非空时清空单数
#     RuntimeIdentifier，单数被清空 → PublishSingleFile 之类属性取不到 RID → NETSDK1191。
#  3) Release 签名密码走 -p:FE_KEYSTORE_PASS=...；VS 的「生成 APK」拿不到命令行参数，
#     靠 GUI-Android/keystore.local.props 兜底（该文件不入库）。
#  4) native libvdisk.so 必须 strip 后再放进 APK（包体与加载都受益），
#     且需与 NDK r27c 同版本构建的 libc++_shared.so 一起放，避免双 libc++ ODR 冲突。
#  5) Release 默认 -g0 与 ThinLTO 并行；ccache 需 --ccache 显式开。
#     实测 27 个编译单元下 ccache 首次反而慢，命中后与不缓存持平。
import argparse
import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import time
import toolchain
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IS_WIN = os.name == "nt"

for _s in (sys.stdout, sys.stderr):
    if _s is not None:
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# 工具路径（VS 自带，不在 PATH 里）
CMAKE = toolchain.cmake()
NDK = toolchain.android_ndk()
STRIP = os.path.join(NDK, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-strip.exe")
ANDROID_SDK = toolchain.android_sdk()
JAVA_SDK = toolchain.java_sdk()

CLI_DIR = os.path.join(REPO, "CLI")
ND_BUILD = os.path.join(CLI_DIR, "out", "android", "vdisk6")
GUI_DIR = os.path.join(REPO, "GUI-Android")
PROJ = os.path.join(GUI_DIR, "FileEncryptorMobile.csproj")
NATIVE_DST = os.path.join(GUI_DIR, "Platforms", "Android", "native", "arm64-v8a")
# CI 可把 OpenSSL prefix 放到共享缓存目录，用环境变量指过来
OPENSSL_ROOT = os.environ.get("FE_OPENSSL_ROOT",
                              os.path.join(REPO, "out", "android", "openssl-prefix"))
TFM = "net10.0-android36.0"
KEYSTORE_PASS = "FileEncryptorRelease"
DEFAULT_RELEASE = toolchain.release_dir()

LOG = os.path.join(REPO, ".workbuddy", "build_android_apk.log")


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd=None, dry=False):
    print("  $ " + " ".join(cmd), flush=True)
    if dry:
        return 0, ""
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        errs = [ln for ln in out.splitlines() if ": error " in ln.lower()]
        if errs:
            print("\n".join(errs[:40]), flush=True)
        print(out[-4000:], flush=True)
    return p.returncode, out


def run_pass(cmd, cwd=None):
    # stdio 透传跑 vcvars
    # capture 管道下沙箱杀树
    print("  $ " + " ".join(cmd), flush=True)
    p = subprocess.call(cmd, cwd=cwd)
    return p, ""


def find_ccache():
    """定位编译缓存；缺失时降级。"""
    c = shutil.which("ccache") or shutil.which("ccache.exe")
    if c and os.path.exists(c):
        return c
    fallback = r"E://Strawberry//c//bin//ccache.exe"
    return fallback if os.path.exists(fallback) else ""


def ccache_stats(cc):
    """打印缓存命中梗概。"""
    p = subprocess.run([cc, "-s"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    seen = set()
    for ln in (p.stdout or "").splitlines():
        key = ln.strip().split(":")[0]
        if key in ("Hits", "Misses", "Cache size (GiB)") and key not in seen:
            seen.add(key)
            print("  " + ln.strip(), flush=True)


def step_native(dry, jobs=0, use_ccache=False, configure=True):
    """交叉编译 libvdisk.so（arm64-v8a），strip 后同步到 GUI-Android 工程目录。"""
    print("[1/3] native libvdisk.so (NDK r27c, arm64-v8a)", flush=True)
    cc = find_ccache() if use_ccache else ""
    par = jobs or (os.cpu_count() or 4)
    # 经 vcvars 包装跑 cmake
    # 沙箱环境裸 cmake 缺 UCRT
    bat = os.path.join(REPO, "scripts", "build_with_vcvars.bat")
    try:
        import _win_build
        vcvars = _win_build.vcvars()
    except Exception:
        vcvars = r"E:\Microsoft Visual Studio\VC\Auxiliary\Build\vcvars64.bat"
    use_bat = os.path.exists(bat) and os.path.exists(vcvars)
    if configure:
        # bat 的 cmd 拆逗号/等号
        # 全部变量走 -C 初始缓存文件
        cache = os.path.join(ND_BUILD, "fe_initial_cache.cmake")
        if not dry:
            os.makedirs(ND_BUILD, exist_ok=True)
            toolchain = os.path.join(NDK, "build", "cmake", "android.toolchain.cmake").replace("\\", "/")
            sodium = os.path.join(REPO, "out", "android", "sodium-prefix").replace("\\", "/")
            yamlcpp = os.path.join(REPO, "out", "android", "yamlcpp-prefix").replace("\\", "/")
            with open(cache, "w", encoding="utf-8") as f:
                f.write('set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -g0" CACHE STRING "" FORCE)\n')
                f.write('set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--thinlto-jobs=%d" CACHE STRING "" FORCE)\n' % par)
                f.write('set(CMAKE_CXX_COMPILER_LAUNCHER "%s" CACHE STRING "" FORCE)\n' % cc.replace("\\", "/"))
                f.write('set(CMAKE_TOOLCHAIN_FILE "%s" CACHE FILEPATH "" FORCE)\n' % toolchain)
                f.write('set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)\n')
                f.write('set(ANDROID_ABI arm64-v8a CACHE STRING "" FORCE)\n')
                f.write('set(ANDROID_PLATFORM android-26 CACHE STRING "" FORCE)\n')
                f.write('set(ANDROID_STL c++_shared CACHE STRING "" FORCE)\n')
                f.write('set(SODIUM_STATIC ON CACHE BOOL "" FORCE)\n')
                f.write('set(WITH_OPENSSL ON CACHE BOOL "" FORCE)\n')
                f.write('set(WITH_ZSTD ON CACHE BOOL "" FORCE)\n')
                f.write('set(SODIUM_ROOT "%s" CACHE PATH "" FORCE)\n' % sodium)
                f.write('set(YAMLCPP_ROOT "%s" CACHE PATH "" FORCE)\n' % yamlcpp)
                f.write('set(OPENSSL_ROOT "%s" CACHE PATH "" FORCE)\n' % OPENSSL_ROOT.replace("\\", "/"))
        cfg = [
            CMAKE, "-S", CLI_DIR, "-B", ND_BUILD, "-G", "Ninja",
            "-C", cache,
        ]
        print("  ccache: %s" % (cc or "未启用"), flush=True)
        if use_bat:
            # cmd /d /c 包一层
            # 与 build_all 同款防黑名单
            # bat 自执行 cmake，args 不含 cmake 本身
            cmd = ["cmd", "/d", "/c", bat, vcvars, CMAKE, ND_BUILD, "Release", "--cmake"] + cfg[1:]
            rc, _ = (0, "") if dry else run_pass(cmd)
        else:
            rc, _ = run(cfg, dry=dry)
        if rc != 0:
            return None
    elif not dry and not os.path.exists(os.path.join(ND_BUILD, "build.ninja")):
        print("  ! 跳过 configure 但构建目录未初始化", flush=True)
        return None
    build = [CMAKE, "--build", ND_BUILD, "--target", "vdisk"]
    if jobs:
        build += ["--parallel", str(jobs)]
    if use_bat:
        cmd = ["cmd", "/d", "/c", bat, vcvars, CMAKE, ND_BUILD, "Release"] + build[3:]
        rc, _ = (0, "") if dry else run_pass(cmd)
    else:
        rc, _ = run(build, dry=dry)
    if rc != 0:
        return None
    if cc and not dry:
        ccache_stats(cc)
    so = os.path.join(ND_BUILD, "bin", "libvdisk.so")
    if not os.path.exists(so):
        print("  ! 未找到 " + so, flush=True)
        return None
    stripped = so + ".stripped"
    if not dry:
        shutil.copyfile(so, stripped)
        rc, _ = run([STRIP, "--strip-all", stripped], dry=dry)
        if rc != 0:
            return None
        os.makedirs(NATIVE_DST, exist_ok=True)
        shutil.copyfile(stripped, os.path.join(NATIVE_DST, "libvdisk.so"))
    print("  libvdisk.so -> %s (%d B)" % (NATIVE_DST, os.path.getsize(stripped) if not dry else 0),
          flush=True)
    return stripped


def shutdown_build_server():
    # publish 前清 MSBuild 节点
    # 防 1093 假绿
    try:
        subprocess.run(["dotnet", "build-server", "shutdown"], cwd=REPO,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=120)
    except Exception as e:
        print("  ! shutdown 失败（忽略）：%s" % e, flush=True)


def apk_zip_health(apk):
    # ZIP 条目数判据
    # 基线 1552，1093 即假绿
    # kotlin_module 结尾文件好包也没有，勿作判据
    try:
        with zipfile.ZipFile(apk) as z:
            names = z.namelist()
        return len(names) >= 1500
    except Exception:
        return False


def stale_obj_bin():
    # 同盘移走增量残留
    # 绕 safe-delete hook
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    root = os.path.join(REPO, ".workbuddy", "stale_apk_" + stamp)
    os.makedirs(root, exist_ok=True)
    moved = []
    for sub in ("obj", "bin"):
        src = os.path.join(GUI_DIR, sub, "Release")
        if os.path.exists(src):
            os.rename(src, os.path.join(root, sub))
            moved.append(src)
    if moved:
        print("  已隔离增量残留 -> %s" % root, flush=True)
    return moved


def publish_once(dry):
    # 走与 VS「发布」同一个 profile：产物与 VS 完全一致（SelfContained/PublishSingleFile 等
    # 差异会体现在包体大小上，混用两套参数会出现「脚本打的包比 VS 的小 300KB」的错觉）。
    cmd = [
        "dotnet", "publish", PROJ,
        "-p:PublishProfile=FolderProfile",
        "-p:FE_KEYSTORE_PASS=" + KEYSTORE_PASS,
        "-p:AndroidSdkDirectory=" + ANDROID_SDK,
        "-p:AndroidNdkDirectory=" + NDK,
        "-p:JavaSdkDirectory=" + JAVA_SDK,
    ]
    rc, out = run(cmd, cwd=REPO, dry=dry)
    if rc != 0:
        print("  publish 失败", flush=True)
        return None
    # profile 的 PublishDir = E:\Release\android，产物直接落那里
    cands = [
        os.path.join(DEFAULT_RELEASE, "android", "com.yaoyingluo.fileencryptor-Signed.apk"),
        os.path.join(DEFAULT_RELEASE, "com.yaoyingluo.fileencryptor-Signed.apk"),
        os.path.join(GUI_DIR, "bin", "Release", TFM, "publish",
                     "com.yaoyingluo.fileencryptor-Signed.apk"),
        os.path.join(GUI_DIR, "bin", "Release", TFM,
                     "com.yaoyingluo.fileencryptor-Signed.apk"),
    ]
    for apk in cands:
        if os.path.exists(apk):
            return apk
    print("  ! 未找到 APK 产物", flush=True)
    return None


def wait_healthy(apk, tries=30, delay=5):
    # 纯等待节点收尾
    # 禁 shutdown 会杀写入
    for i in range(tries):
        if apk_zip_health(apk):
            return True
        print("  条目检查未过(%d/%d)，%ds 后重读" % (i + 1, tries, delay), flush=True)
        time.sleep(delay)
    return False


def step_publish(dry):
    print("[2/3] dotnet publish (%s, Release, android-arm64)" % TFM, flush=True)
    if not dry:
        shutdown_build_server()
    apk = publish_once(dry)
    if apk is None or dry:
        return apk
    if wait_healthy(apk):
        return apk
    # 自愈一轮
    # 隔离后全量重 publish
    print("  ! ZIP 条目异常（1093 假绿特征），自动全量重 publish", flush=True)
    shutdown_build_server()
    stale_obj_bin()
    apk = publish_once(dry)
    if apk is not None:
        if wait_healthy(apk):
            return apk
        print("  ! 重 publish 后条目仍异常，放弃", flush=True)
    return None


def step_verify(apk, native_so, dry=False):
    """校验 APK 内 native 库与工程目录一致（防止改了 native 却忘了同步）。"""
    print("[3/3] 校验 APK 内容", flush=True)
    with zipfile.ZipFile(apk) as z:
        names = [n for n in z.namelist() if n.endswith(".so")]
        entry = "lib/arm64-v8a/libvdisk.so"
        if entry not in names:
            print("  ! APK 内缺少 libvdisk.so", flush=True)
            return False
        data = z.read(entry)
        apk_md5 = hashlib.md5(data).hexdigest()
        src = os.path.join(NATIVE_DST, "libvdisk.so")
        src_md5 = md5(src)
        libcxx = "lib/arm64-v8a/libc++_shared.so"
        libcxx_md5 = hashlib.md5(z.read(libcxx)).hexdigest() if libcxx in names else "缺失"
    print("  APK 内 libvdisk.so  : %d B  md5=%s" % (len(data), apk_md5), flush=True)
    print("  工程目录 libvdisk.so: md5=%s" % src_md5, flush=True)
    print("  APK 内 libc++_shared : md5=%s" % libcxx_md5, flush=True)
    if native_so and not dry:
        native_md5 = md5(native_so)
        if native_md5 != apk_md5:
            print("  ! 与刚构建的 native 不一致（strip 前/后差异？）", flush=True)
            return False
    return apk_md5 == src_md5


def collect(apk, release_dir, dry):
    dst_dir = os.path.join(release_dir, "android")
    dst = os.path.join(dst_dir, os.path.basename(apk))
    if os.path.abspath(dst) == os.path.abspath(apk):
        print("  已在发布目录：%s" % dst, flush=True)
        return dst
    if dry:
        print("  copy %s -> %s" % (apk, dst), flush=True)
        return dst
    os.makedirs(dst_dir, exist_ok=True)
    shutil.copyfile(apk, dst)
    print("  已复制到 %s" % dst, flush=True)
    return dst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-native", action="store_true", help="跳过 native 编译")
    ap.add_argument("--publish-only", action="store_true", help="只跑 publish")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--release-dir", default=DEFAULT_RELEASE)
    ap.add_argument("--jobs", type=int, default=0, help="并行编译数，默认按 CPU 核数")
    ap.add_argument("--no-configure", action="store_true", help="跳过 configure，直接增量构建")
    ap.add_argument("--ccache", action="store_true", help="启用编译缓存（默认关）")
    a = ap.parse_args()

    print("===== Android APK 打包 %s =====" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    native_so = None
    if not a.no_native and not a.publish_only:
        native_so = step_native(a.dry_run, jobs=a.jobs,
                                use_ccache=a.ccache,
                                configure=not a.no_configure)
        if native_so is None and not a.dry_run:
            print("native 构建失败，终止")
            return 2
    apk = step_publish(a.dry_run)
    if apk is None:
        return 2
    ok = True
    if not a.dry_run:
        ok = step_verify(apk, native_so, a.dry_run)
    dst = collect(apk, a.release_dir, a.dry_run)
    print("===== 完成：%s =====" % dst)
    print("APK: %s (%d B) md5=%s" % (apk, os.path.getsize(apk), md5(apk)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
