#!/usr/bin/env python3
# coding: utf-8
"""工具链探测"""
import os
import re
import shutil

IS_WIN = os.name == "nt"


class ToolchainError(RuntimeError):
    pass


# 本机路径
_NDK = "E:/Microsoft Visual Studio SDK/Android/AndroidNDK/android-ndk-r27c"
_STRAWBERRY = "E:/Strawberry/perl/lib"
_BASH = ("E:/Git/bin/bash.exe", "E:/Git/usr/bin/bash.exe")
_CMAKE = "E:/Microsoft Visual Studio/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
_SDK = "E:/Microsoft Visual Studio SDK/Android/android-sdk"
_JAVA = "E:/Microsoft Visual Studio SDK/Android/openjdk/jdk-21.0.8"
_RELEASE = "E:/Release" if IS_WIN else "/mnt/e/Release"


def _home():
    return os.path.expanduser("~")


def _exists(p, want):
    # 路径校验
    if not p or not os.path.exists(p):
        return False
    return os.path.isfile(p) if want == "file" else os.path.isdir(p)


def _pick(env, label, cands, want="dir", required=True):
    # 变量优先
    ov = os.environ.get(env, "").strip()
    if ov:
        p = os.path.abspath(ov)
        if _exists(p, want):
            return p
        if required:
            raise ToolchainError("%s 指向路径不存在：%s" % (env, p))
    for c in cands:
        if _exists(c, want):
            return os.path.abspath(c)
    if required:
        raise ToolchainError("未找到 %s，可用 %s 指定" % (label, env))
    return None


def _env_paths(*names):
    # 环境变量
    return [v for n in names for v in (os.environ.get(n, "").strip(),) if v]


def _vkey(s):
    # 版本排序
    nums = tuple(int(n) for n in re.findall(r"[0-9]+", s))
    tail = re.findall(r"[a-z]", s.lower())
    return (nums, tail[-1] if tail else "")


def _local_sdk():
    # 常见位置
    la = os.environ.get("LOCALAPPDATA", "").strip()
    out = []
    if la:
        out.append(os.path.join(la, "Android", "Sdk"))
    out.append(os.path.join(_home(), "Android", "Sdk"))
    out += ["C:/Program Files (x86)/Android/android-sdk", "C:/Android/android-sdk"]
    return out


def git_bash(required=True):
    cands = list(_BASH)
    cands += [
        "C:/Program Files/Git/bin/bash.exe",
        "C:/Program Files/Git/usr/bin/bash.exe",
        "C:/Program Files (x86)/Git/bin/bash.exe",
    ]
    g = shutil.which("git")
    if g:
        # 反推目录
        b = os.path.dirname(os.path.abspath(g))
        for r in (b, os.path.dirname(b), os.path.dirname(os.path.dirname(b))):
            cands.append(os.path.join(r, "bin", "bash.exe"))
            cands.append(os.path.join(r, "usr", "bin", "bash.exe"))
    cands.append(shutil.which("bash"))
    return _pick("FE_GIT_BASH", "Git Bash", cands, "file", required)


def strawberry_lib(required=True):
    cands = [
        _STRAWBERRY,
        "C:/Strawberry/perl/lib",
        "D:/Strawberry/perl/lib",
        os.path.join(_home(), "Strawberry", "perl", "lib"),
    ]
    return _pick("FE_STRAWBERRY_LIB", "Strawberry perl lib", cands, "dir", required)


def android_ndk(required=True):
    # 版本目录
    parents = ["E:/Microsoft Visual Studio SDK/Android/AndroidNDK"]
    la = os.environ.get("LOCALAPPDATA", "").strip()
    if la:
        parents.append(os.path.join(la, "Android", "Sdk", "ndk"))
    parents.append(os.path.join(_home(), "Android", "Sdk", "ndk"))
    for v in _env_paths("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        parents.append(os.path.join(v, "ndk"))
    dirs = []
    for parent in parents:
        if os.path.isdir(parent):
            for n in os.listdir(parent):
                p = os.path.join(parent, n)
                if os.path.isdir(p) and re.search(r"r[0-9]+[a-z]?", n):
                    dirs.append(p)
    dirs.sort(key=_vkey, reverse=True)
    cands = [_NDK] + dirs + _env_paths("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT")
    return _pick("FE_ANDROID_NDK", "Android NDK", cands, "dir", required)


def android_sdk(required=True):
    cands = [_SDK] + _local_sdk() + _env_paths("ANDROID_HOME", "ANDROID_SDK_ROOT")
    return _pick("FE_ANDROID_SDK", "Android SDK", cands, "dir", required)


def java_sdk(required=True):
    roots = [
        "E:/Microsoft Visual Studio SDK/Android/openjdk",
        "C:/Program Files/Java",
        "C:/Program Files/Eclipse Adoptium",
        "C:/Program Files/Microsoft",
        "C:/Program Files/Android/Android Studio",
        os.path.join(_home(), ".gradle", "jdks"),
        "/usr/lib/jvm",
    ]
    dirs = []
    for r in roots:
        if os.path.isdir(r):
            for n in os.listdir(r):
                p = os.path.join(r, n)
                if os.path.isdir(p) and re.search(r"jdk|openjdk|jbr", n, re.I):
                    dirs.append(p)
    j = shutil.which("java")
    if j:
        # 反推目录
        dirs.append(os.path.dirname(os.path.dirname(os.path.abspath(j))))
    dirs.sort(key=_vkey, reverse=True)
    cands = [_JAVA] + dirs + _env_paths("JAVA_HOME")
    return _pick("FE_JAVA_HOME", "Java SDK", cands, "dir", required)


def cmake(required=True):
    cands = [
        _CMAKE,
        "C:/Program Files/CMake/bin/cmake.exe",
        "C:/Program Files (x86)/CMake/bin/cmake.exe",
        "C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe",
        "/usr/bin/cmake",
        shutil.which("cmake"),
    ]
    return _pick("FE_CMAKE", "CMake", cands, "file", required)


def release_dir():
    # 发布目录
    ov = os.environ.get("FE_RELEASE_DIR", "").strip()
    if ov:
        return os.path.abspath(ov)
    cands = [
        _RELEASE,
        os.path.join(_home(), "Release"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out", "Release"),
    ]
    for c in cands:
        if os.path.isdir(c):
            return os.path.abspath(c)
    return os.path.abspath(_RELEASE)


# 探测入口
if __name__ == "__main__":
    for name, fn in (
        ("git_bash", git_bash),
        ("strawberry_lib", strawberry_lib),
        ("android_ndk", android_ndk),
        ("android_sdk", android_sdk),
        ("java_sdk", java_sdk),
        ("cmake", cmake),
        ("release_dir", release_dir),
    ):
        try:
            print("%-16s %s" % (name, fn()))
        except ToolchainError as e:
            print("%-16s %s" % (name, e))
