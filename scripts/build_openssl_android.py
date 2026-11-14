#!/usr/bin/env python3
# 交叉编译 OpenSSL 4.x 静态库（arm64-v8a, android-26），供 libvdisk.so 链接。
#
# 用法：
#   python scripts/build_openssl_android.py            # 构建到 out/android/openssl-prefix
#   python scripts/build_openssl_android.py --force    # 重编并覆盖，旧产物保留
#   python scripts/build_openssl_android.py --jobs 12   # 指定并行数
#   python scripts/build_openssl_android.py --no-ccache # 禁用编译缓存
#   python scripts/build_openssl_android.py --prefix X  # 产物放到共享缓存目录
#   python scripts/build_openssl_android.py --dry-run  # 只打印命令
#
# 关键点（踩过的坑）：
#  1) 必须走 Git Bash（MSYS）+ 其自带 cygwin perl（/usr/bin/perl，Unix 路径语义）。
#     Strawberry perl（MSWin32）会被 OpenSSL 的 unix-checker.pm 直接拒绝
#     （「doesn't produce Unix like paths」），且其 File::Spec->path() 会把
#     「E:\x」按「:」拆散，which() 永远找不到 NDK 工具——原生 Windows perl 不可行。
#  2) python 只做编排：把所有路径转成 MSYS 形式（/e/...）后经 bash -c 执行，
#     Configure/make/perl 全程在 MSYS 世界里跑（与 libsodium android-build.sh 同范式）。
#  3) 复用 NDK r27c 的 clang + make（NDK prebuilt 自带 make.exe），不依赖系统 make。
#  4) Configure android-arm64 + -D__ANDROID_API__=26 与 build_android_apk.py 的
#     ANDROID_PLATFORM=android-26 对齐；--static 只产 libcrypto.a / libssl.a（PIC，可链入 .so）。
#  5) --libdir=lib 避免落进 lib64/；install_sw 跳过文档，仅装 lib + include/openssl。
#  6) 与 sodium-prefix / yamlcpp-prefix 同一范式：本脚本是「生产者」，
#     build_android_apk.py 只「消费」产物（不重编），须先跑本脚本。
#  7) Configure 加 no-apps 只编库；make 默认用 ccache 包 clang，二次构建命中缓存。
#     上百个编译单元，缓存收益与只有 27 个单元的 vdisk 不同。
import argparse
import os
import shutil
import subprocess
import sys
import toolchain

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IS_WIN = os.name == "nt"

for _s in (sys.stdout, sys.stderr):
    if _s is not None:
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

OSSL_SRC = os.path.join(REPO, "Third Party", "openssl")
NDK = toolchain.android_ndk()
NDK_LLVM = os.path.join(NDK, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin")
NDK_MAKE = os.path.join(NDK, "prebuilt", "windows-x86_64", "bin")
PREFIX = os.path.join(REPO, "out", "android", "openssl-prefix")
API = 26
LOG = os.path.join(REPO, ".workbuddy", "build_openssl_android.log")
# Git 自带 cygwin perl 缺两个纯 Perl 模块（IPC::Cmd 依赖链），从 Strawberry 借
# 纯 .pm 建 shim；MakeMaker 用最小桩（IPC::Cmd::can_run 只用 MM->maybe_command）
STRAWBERRY_LIB = toolchain.strawberry_lib()
PERL_SHIM = os.path.join(REPO, ".workbuddy", "perl-shim")

MM_STUB = """\
# 最小桩：仅为 Git cygwin perl 补齐 IPC::Cmd::can_run 所需的 MM->maybe_command
package ExtUtils::MakeMaker;
use strict; use warnings;
sub import { }
package MM;
sub maybe_command {
    my ($self, $file) = @_;
    return $file if defined $file && -f $file && -x $file;
    return;
}
1;
"""


def ensure_perl_shim():
    """Git cygwin perl 缺 Locale::Maketext(+Simple)/ExtUtils::MakeMaker/Pod 全套，
    拷纯 .pm 建 shim；PERL5LIB 在本环境传不进 perl，只能 -I 注入。"""
    os.makedirs(os.path.join(PERL_SHIM, "Locale", "Maketext"), exist_ok=True)
    os.makedirs(os.path.join(PERL_SHIM, "ExtUtils"), exist_ok=True)
    for src, dst in (
        (os.path.join(STRAWBERRY_LIB, "Locale", "Maketext.pm"),
         os.path.join(PERL_SHIM, "Locale", "Maketext.pm")),
        (os.path.join(STRAWBERRY_LIB, "Locale", "Maketext", "Simple.pm"),
         os.path.join(PERL_SHIM, "Locale", "Maketext", "Simple.pm")),
    ):
        if not os.path.exists(dst):
            shutil.copyfile(src, dst)
    stub = os.path.join(PERL_SHIM, "ExtUtils", "MakeMaker.pm")
    if not os.path.exists(stub):
        with open(stub, "w", encoding="utf-8", newline="\n") as f:
            f.write(MM_STUB)
    # Pod 全套（configdata.pm 顶层 use Pod::Usage → Pod::Text → Pod::Simple 链）
    _s_pod = os.path.join(STRAWBERRY_LIB, "Pod")
    _d_pod = os.path.join(PERL_SHIM, "Pod")
    for sub in ("", "Text", "Simple"):
        os.makedirs(os.path.join(_d_pod, sub) if sub else _d_pod, exist_ok=True)
        pattern = os.path.join(_s_pod, sub, "*.pm") if sub else os.path.join(_s_pod, "*.pm")
        import glob as _glob
        for src in _glob.glob(pattern):
            dst = os.path.join(_d_pod, sub, os.path.basename(src))
            if not os.path.exists(dst):
                shutil.copyfile(src, dst)
    return to_msys(PERL_SHIM)


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


def to_msys(p):
    # Windows 路径转 MSYS 形式：E:\foo\bar -> /e/foo/bar
    p = p.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        return "/" + p[0].lower() + p[2:]
    return p


def find_bash():
    # 工具链探测
    return toolchain.git_bash(required=False)


def run_bash(script, dry=False):
    bash = find_bash()
    if not bash:
        print("! 找不到 bash.exe（需要 Git Bash）", flush=True)
        return 2, ""
    print("  $ bash -c <script>  (" + bash + ")", flush=True)
    for ln in script.rstrip().splitlines():
        print("    | " + ln, flush=True)
    if dry:
        return 0, ""
    p = subprocess.run([bash, "-c", script], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="强制重编并覆盖安装，旧产物保留")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--jobs", type=int, default=0, help="并行编译数，默认按 CPU 核数")
    ap.add_argument("--prefix", default=PREFIX, help="产物前缀，可指向共享缓存目录")
    ap.add_argument("--no-ccache", action="store_true", help="禁用编译缓存")
    a = ap.parse_args()

    prefix = os.path.abspath(a.prefix)
    if not os.path.isdir(OSSL_SRC) or not os.path.exists(os.path.join(OSSL_SRC, "Configure")):
        print("! 找不到 OpenSSL 源码：%s" % OSSL_SRC, flush=True)
        return 2

    print("===== OpenSSL 交叉编译 (android-arm64, api %d, MSYS+cygwin perl) =====" % API)
    print("  源码 : %s" % OSSL_SRC)
    print("  前缀 : %s" % prefix)

    lib_a = os.path.join(prefix, "lib", "libcrypto.a")
    hdr = os.path.join(prefix, "include", "openssl", "crypto.h")
    if os.path.exists(lib_a) and os.path.exists(hdr) and not a.force:
        print("  已有 libcrypto.a 与头文件，跳过（--force 可重编）", flush=True)
        return 0

    nproc = a.jobs or (os.cpu_count() or 4)
    cc = "" if a.no_ccache else find_ccache()
    cc_arg = " CC='%s clang'" % to_msys(cc) if cc else ""
    print("  ccache: %s" % (cc or "未启用"), flush=True)
    print("  并行  : %d" % nproc, flush=True)
    src_m = to_msys(OSSL_SRC)
    pfx_m = to_msys(prefix)
    ndk_m = to_msys(NDK)
    llvm_m = to_msys(NDK_LLVM)
    mk_m = to_msys(NDK_MAKE)
    shim_m = ensure_perl_shim() if not a.dry_run else to_msys(PERL_SHIM)

    script = "\n".join([
        "set -e",
        "export ANDROID_NDK_ROOT='%s'" % ndk_m,
        # 单引号段内 $PATH 不展开，须移出引号再拼接
        "export PATH='%s:%s':\"$PATH\"" % (llvm_m, mk_m),
        # Configure 会再起 `perl configdata.pm` 子进程，shim 必须经环境对所有 perl 生效
        "export PERL5LIB='%s':\"$PERL5LIB\"" % shim_m,
        "export PERL5OPT='-I%s'" % shim_m,
        "cd '%s'" % src_m,
        "perl -I'%s' Configure android-arm64 -D__ANDROID_API__=%d"
        " --prefix='%s' --libdir=lib --static no-shared no-tests no-docs"
        " no-ui-console no-external-tests no-apps" % (shim_m, API, pfx_m),
        "make -j%d%s" % (nproc, cc_arg),
        # no-apps 下 install_sw 偶尔仍要程序目标，失败就只装库与头
        "make install_sw%s || make install_dev%s" % (cc_arg, cc_arg),
        "echo BUILD_OK",
    ])

    rc, out = run_bash(script, dry=a.dry_run)
    if out:
        tail = "\n".join(out.splitlines()[-60:])
        print(tail, flush=True)
    if rc != 0 or (not a.dry_run and "BUILD_OK" not in out):
        print("  构建失败（exit=%d）" % rc, flush=True)
        return 2
    if cc and not a.dry_run:
        ccache_stats(cc)

    if a.dry_run:
        print("  [dry-run] 跳过产物校验", flush=True)
        return 0

    if not os.path.exists(lib_a):
        print("  ! 未找到 %s" % lib_a, flush=True)
        return 2
    if not os.path.exists(hdr):
        print("  ! 未找到 %s" % hdr, flush=True)
        return 2

    print("  libcrypto.a : %d B" % os.path.getsize(lib_a), flush=True)
    print("  include     : %s" % os.path.join(prefix, "include", "openssl"))
    print("===== 完成：%s =====" % prefix)
    return 0


if __name__ == "__main__":
    sys.exit(main())
