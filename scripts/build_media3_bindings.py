# -*- coding: utf-8 -*-
"""重建 Media3 本地绑定包（9 个 nupkg）。

用法：
    python scripts/build_media3_bindings.py            校验现有本地包
    python scripts/build_media3_bindings.py --rebind   从绑定源码重新生成
    python scripts/build_media3_bindings.py --dry-run  只打印将执行的命令

前置（仅 --rebind 需要）：.NET 10 SDK + Android workload、JDK 21、ANDROID_SDK_ROOT、
Cake 相关依赖由 binderator 工程自行还原。重建耗时较长且需 Maven 网络，建议后台运行。

流程按 Third Party/android-libraries/BUILDING.md 与 build/cake/binderate.cake 推导：
直接用 --config-file 指向已裁剪的 config.media3.json，不改第三方仓库的 config.json。
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBS = os.path.join(REPO, "Third Party", "android-libraries")
CONFIG = os.path.join(REPO, "build", "media3-bindings", "config.media3.json")
FEED = os.path.join(REPO, "build", "media3-bindings", "nuget")
OUTPUT = os.path.join(LIBS, "output")
BINDERATOR = os.path.join(
    LIBS, "util", "Xamarin.AndroidBinderator",
    "Xamarin.AndroidBinderator.Tool", "Xamarin.AndroidBinderator.Tool.csproj")
SLN = os.path.join(LIBS, "generated", "Media3.sln")

VERSION = "1.11.1"
PACKAGE_IDS = (
    "Xamarin.AndroidX.Media3.Common",
    "Xamarin.AndroidX.Media3.Container",
    "Xamarin.AndroidX.Media3.Database",
    "Xamarin.AndroidX.Media3.DataSource",
    "Xamarin.AndroidX.Media3.Decoder",
    "Xamarin.AndroidX.Media3.ExoPlayer",
    "Xamarin.AndroidX.Media3.Extractor",
    "Xamarin.AndroidX.Media3.Session",
    "Xamarin.AndroidX.Media3.Ui",
)


def run(cmd, cwd=None, dry=False):
    print("+ " + " ".join(cmd), flush=True)
    if dry:
        return 0
    rc = subprocess.call(cmd, cwd=cwd)
    print("  exit=%d" % rc, flush=True)
    return rc


def verify():
    missing = []
    for pid in PACKAGE_IDS:
        f = os.path.join(FEED, "%s.%s.nupkg" % (pid, VERSION))
        if os.path.isfile(f):
            print("  OK %-45s %9d B" % (pid, os.path.getsize(f)))
        else:
            print("  MISSING " + f)
            missing.append(pid)
    extra = [os.path.basename(p) for p in glob.glob(os.path.join(FEED, "*.nupkg"))
             if not any(os.path.basename(p).startswith(pid + "." + VERSION)
                        for pid in PACKAGE_IDS)]
    print("verify: %d/%d 包就绪" % (len(PACKAGE_IDS) - len(missing), len(PACKAGE_IDS)))
    if extra:
        print("注意：feed 里有未列入清单的包 -> " + ", ".join(sorted(extra)))
    return not missing


def precheck():
    ok = True
    for path, label in ((CONFIG, "裁剪配置"), (BINDERATOR, "binderator 工程")):
        if os.path.isfile(path):
            print("  OK %s %s" % (label, path))
        else:
            print("  缺失 %s %s" % (label, path))
            ok = False
    if shutil.which("dotnet") is None:
        print("  缺失 dotnet")
        ok = False
    if not os.environ.get("ANDROID_SDK_ROOT"):
        print("  提示：ANDROID_SDK_ROOT 未设置，binderator 可能需要它")
    return ok


def rebind(dry=False):
    if not precheck():
        return 2
    steps = [
        (["dotnet", "run", "--project", BINDERATOR, "--",
          "binderate", "--config-file", CONFIG, "--base-path", LIBS], LIBS),
        (["dotnet", "build", "generated/Media3.sln", "-c", "Release",
          "-v:q", "-nologo"], LIBS),
        (["dotnet", "msbuild", "generated/Media3.sln", "-t:Pack",
          "-p:Configuration=Release", "-p:NoBuild=true",
          "-p:PackageOutputPath=" + OUTPUT], LIBS),
    ]
    for cmd, cwd in steps:
        if run(cmd, cwd=cwd, dry=dry) != 0:
            print("重建中断：上一步失败", file=sys.stderr)
            return 1
    if dry:
        return 0

    if not os.path.isfile(SLN):
        print("未生成 Media3.sln: " + SLN, file=sys.stderr)
        return 1
    os.makedirs(FEED, exist_ok=True)
    for pid in PACKAGE_IDS:
        name = "%s.%s.nupkg" % (pid, VERSION)
        hits = glob.glob(os.path.join(OUTPUT, name))
        if not hits:
            hits = glob.glob(os.path.join(LIBS, "output", "**", name), recursive=True)
        if not hits:
            print("未产出 " + name, file=sys.stderr)
            return 1
        shutil.copyfile(hits[0], os.path.join(FEED, name))
        print("install " + name)
    return 0 if verify() else 1


def main():
    ap = argparse.ArgumentParser(description="重建 Media3 本地绑定包")
    ap.add_argument("--rebind", action="store_true", help="从绑定源码重新生成")
    ap.add_argument("--dry-run", action="store_true", help="只打印命令")
    a = ap.parse_args()
    if a.rebind:
        return rebind(dry=a.dry_run)
    if a.dry_run:
        return rebind(dry=True)
    print("校验本地 feed: " + FEED)
    return 0 if verify() else 1


if __name__ == "__main__":
    sys.exit(main())
