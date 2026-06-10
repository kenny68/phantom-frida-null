#!/usr/bin/env python3
"""
build16.py — frida 16.x 兼容构建脚本
适配 phantom-frida 的 patch 逻辑，但使用 frida 16.x 的 make 构建系统
用法：
  python3 build16.py --version 16.2.1 --name kkallptr --arch android-arm64 \
                     --port 1234 --extended --verify \
                     --skip-clone --ndk-path build/android-ndk-r29
"""

import argparse
import os
import sys
import subprocess
import shutil
import glob
import re
from pathlib import Path

# ── ANSI 颜色 ──────────────────────────────────────────────
def ok(msg):   print(f"\033[32m[OK]\033[0m   {msg}")
def info(msg): print(f"\033[34m[INFO]\033[0m {msg}")
def warn(msg): print(f"\033[33m[WARN]\033[0m  {msg}")
def err(msg):  print(f"\033[31m[ERROR]\033[0m {msg}")
def hdr(msg):  print(f"\033[1m[HEADER]\033[0m {'='*60}\n[HEADER] {msg}\n[HEADER] {'='*60}")

# ── 参数解析 ────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="phantom-frida 16.x builder")
    p.add_argument("--version",    "-v", required=True)
    p.add_argument("--name",       "-n", default="ajeossida")
    p.add_argument("--arch",       "-a", default="android-arm64")
    p.add_argument("--port",       "-p", default="")
    p.add_argument("--extended",   "-e", action="store_true")
    p.add_argument("--temp-fixes",       action="store_true")
    p.add_argument("--verify",           action="store_true")
    p.add_argument("--skip-build",       action="store_true")
    p.add_argument("--skip-clone",       action="store_true")
    p.add_argument("--ndk-path",         default="")
    p.add_argument("--work-dir",         default="build")
    p.add_argument("--output-dir",       default="output")
    return p.parse_args()

# ── 执行 shell 命令 ─────────────────────────────────────────
def run(cmd, cwd=None, env=None, check=True):
    info(f"$ {cmd}")
    result = subprocess.run(
        cmd, shell=True, cwd=cwd, env=env,
        stdout=sys.stdout, stderr=sys.stderr
    )
    if check and result.returncode != 0:
        err(f"Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    return result.returncode

# ── 递归替换文件内容 ────────────────────────────────────────
def replace_in_files(root, old, new, extensions=None, count_ref=None):
    total = 0
    for path in Path(root).rglob("*"):
        if path.is_file() and ".git" not in str(path):
            if extensions and path.suffix not in extensions:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                if old in text:
                    new_text = text.replace(old, new)
                    path.write_text(new_text, encoding="utf-8")
                    total += text.count(old)
            except Exception:
                pass
    if count_ref is not None:
        count_ref[0] = total
    return total

# ── 重命名文件名 ────────────────────────────────────────────
def rename_files(root, old, new):
    renamed = 0
    for path in sorted(Path(root).rglob("*"), reverse=True):
        if ".git" in str(path):
            continue
        if old in path.name:
            new_name = path.parent / path.name.replace(old, new)
            path.rename(new_name)
            renamed += 1
    return renamed

# ── PHASE 1: 全局字符串替换 ─────────────────────────────────
def phase1_global_patches(frida_dir, name, name_cap):
    hdr("PHASE 1: Global source patches")

    name_cap = name.capitalize()

    patches = [
        ("libfrida-agent-modulated", f"lib{name}-agent-modulated"),
        ("re.frida.Helper",          f"re.{name}.Helper"),
        ("re.frida.helper",          f"re.{name}.helper"),
        ("re.frida.Gadget",          f"re.{name}.Gadget"),
        ("package re.frida;",        f"package re.{name};"),
        ("re.frida.server",          f"re.{name}.server"),
        ("frida-helper-32",          f"{name}-helper-32"),
        ("frida-helper-64",          f"{name}-helper-64"),
        ("get_frida_helper_",        f"get_{name}_helper_"),
        ("frida-helper",             f"{name}-helper"),
        ('"/frida-"',                f'\"/{name}-\"'),
        ("'frida-agent'",            f"'{name}-agent'"),
        ('"frida-agent"',            f'"{name}-agent"'),
        ("frida-agent-",             f"{name}-agent-"),
        ("get_frida_agent_",         f"get_{name}_agent_"),
        (f"'FridaAgent'",            f"'{name_cap}Agent'"),
        ('"gum-js-loop"',            f'"{name}-js-loop"'),
        ("'frida'",                  f"'{name}'"),
    ]

    for old, new in patches:
        cnt = replace_in_files(frida_dir, old, new)
        if cnt:
            ok(f"  {old} -> {new} ({cnt})")
        else:
            warn(f"  {old} -> (not found)")

    # 重命名文件
    cnt = rename_files(frida_dir, "frida-agent", f"{name}-agent")
    cnt += rename_files(frida_dir, "frida-helper", f"{name}-helper")
    cnt += rename_files(frida_dir, "frida-server", f"{name}-server")
    ok(f"Renamed {cnt} files on disk")
    ok("Global source patches complete")

# ── PHASE 2: 定向补丁 ──────────────────────────────────────
def phase2_targeted_patches(frida_dir, name):
    hdr("PHASE 2: Targeted file patches")

    # SELinux 标签
    selinux_patches = [
        ('"frida_file"',   f'"{name}_file"'),
        ('"frida_memfd"',  f'"{name}_memfd"'),
        (":frida_file",    f":{name}_file"),
        (":frida_memfd",   f":{name}_memfd"),
    ]
    for old, new in selinux_patches:
        cnt = replace_in_files(frida_dir, old, new)
        if cnt:
            ok(f"  SELinux: {old} -> {new} ({cnt})")

    ok("Targeted patches complete")

# ── PHASE 2.5: 扩展反检测 ──────────────────────────────────
def phase25_extended_patches(frida_dir, name):
    hdr("PHASE 2.5: Extended anti-detection patches")

    name_cap = name.capitalize()
    extended_patches = [
        ("FridaGadget",  f"{name_cap}Gadget"),
        ("FridaPortal",  f"{name_cap}Portal"),
        ("FridaInject",  f"{name_cap}Inject"),
        ('".frida"',     f'".{name}"'),
        ('"frida-"',     f'"{name}-"'),
    ]
    for old, new in extended_patches:
        cnt = replace_in_files(frida_dir, old, new)
        if cnt:
            ok(f"  {old} -> {new} ({cnt})")
        else:
            warn(f"  {old} -> (not found)")

    ok("Extended patches complete")

# ── 端口替换 ────────────────────────────────────────────────
def patch_port(frida_dir, port):
    if not port:
        return
    info(f"Patching default port 27042 -> {port}")
    cnt = replace_in_files(frida_dir, "27042", str(port))
    ok(f"Port patched ({cnt} occurrences)")

# ── frida 16.x make 构建 ────────────────────────────────────
def build_frida16(frida_dir, arch, ndk_path, output_dir):
    hdr(f"Building for {arch}")

    # arch 映射
    arch_map = {
        "android-arm64": "arm64",
        "android-arm":   "arm",
        "android-x86_64":"x86_64",
        "android-x86":   "x86",
    }
    make_arch = arch_map.get(arch, "arm64")

    env = os.environ.copy()
    if ndk_path:
        env["ANDROID_NDK_ROOT"] = os.path.abspath(ndk_path)
        env["ANDROID_NDK_HOME"] = os.path.abspath(ndk_path)
        info(f"NDK: {env['ANDROID_NDK_ROOT']}")

    # frida 16.x 用 make 构建 server
    target = f"server-android-{make_arch}"
    info(f"make target: {target}")

    # frida 16.x 需要 NDK r25，修改 setup-env.sh 跳过版本检查
      setup_env = os.path.join(frida_dir, "releng", "setup-env.sh")
      if os.path.exists(setup_env):
          with open(setup_env, "r") as f:
              content = f.read()
          # 允许任何 NDK 版本
          content = re.sub(r'ndk_required=r\d+\w*', 'ndk_required=r25c', content)
          with open(setup_env, "w") as f:
              f.write(content)
          info("Patched releng/setup-env.sh: ndk_required -> r25c")

    # 先 make 依赖
    rc = run(
        f"make {target}",
        cwd=frida_dir,
        env=env,
        check=False
    )

    if rc != 0:
        # 尝试只构建 core
        warn(f"make {target} failed (rc={rc}), trying frida-core...")
        rc = run(
            f"make core-android-{make_arch}",
            cwd=frida_dir,
            env=env,
            check=False
        )
        if rc != 0:
            err(f"Build failed with exit code {rc}")
            sys.exit(rc)

    # 收集产物
    os.makedirs(output_dir, exist_ok=True)
    build_output = Path(frida_dir) / "build"

    # 查找 frida-server 二进制
    patterns = [
        f"build/frida-android-{make_arch}/bin/frida-server",
        f"build/frida_thin-android-{make_arch}/bin/frida-server",
        f"build/tmp-android-{make_arch}/frida-server",
    ]

    found = False
    for pattern in patterns:
        matches = glob.glob(os.path.join(frida_dir, pattern))
        if matches:
            src = matches[0]
            info(f"Found server binary: {src}")
            found = True
            break

    if not found:
        # 递归查找
        warn("Searching for frida-server binary...")
        for p in Path(frida_dir).rglob("frida-server"):
            if p.is_file() and ".git" not in str(p):
                src = str(p)
                info(f"Found: {src}")
                found = True
                break

    if not found:
        err("Could not find built frida-server binary!")
        sys.exit(1)

    return src

# ── 收集并重命名产物 ────────────────────────────────────────
def collect_artifacts(src_binary, name, version, arch, output_dir):
    hdr("Collecting artifacts")
    os.makedirs(output_dir, exist_ok=True)

    out_name = f"{name}-server-{version}-{arch}"
    out_path = os.path.join(output_dir, out_name)
    shutil.copy2(src_binary, out_path)
    ok(f"Copied: {out_name}")

    # gzip 压缩
    import gzip
    gz_path = out_path + ".gz"
    with open(out_path, "rb") as f_in:
        with gzip.open(gz_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    ok(f"Compressed: {out_name}.gz")

    return out_path

# ── verify: 扫描残留 frida 字符串 ──────────────────────────
def verify_binary(binary_path):
    hdr("Binary verification")
    result = subprocess.run(
        ["strings", binary_path],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    frida_lines = [l for l in lines if "frida" in l.lower()]
    if frida_lines:
        warn(f"Found {len(frida_lines)} residual 'frida' strings:")
        for l in frida_lines[:20]:
            warn(f"  {l}")
    else:
        ok("No residual 'frida' strings found!")

# ── 主流程 ──────────────────────────────────────────────────
def main():
    args = parse_args()

    version    = args.version
    name       = args.name.lower()
    name_cap   = name.capitalize()
    arch       = args.arch
    port       = args.port
    extended   = args.extended
    work_dir   = os.path.abspath(args.work_dir)
    output_dir = os.path.abspath(args.output_dir)
    ndk_path   = args.ndk_path
    frida_dir  = os.path.join(work_dir, "frida")

    hdr("Custom Frida 16.x Builder")
    info(f"Version:  Frida {version} (major: 16)")
    info(f"Name:     '{name}'")
    info(f"Archs:    {arch}")
    info(f"Port:     {port or '27042 (default)'}")
    info(f"Extended: {extended}")
    info(f"Work dir: {work_dir}")
    info(f"Output:   {output_dir}")
    info(f"NDK:      {os.path.abspath(ndk_path) if ndk_path else 'auto'}")

    # ── 克隆源码 ──
    if not args.skip_clone:
        if os.path.exists(frida_dir):
            shutil.rmtree(frida_dir)
        hdr("Cloning Frida source")
        run(
            f"git clone --branch {version} --depth 1 "
            f"https://github.com/frida/frida.git {frida_dir}"
        )
        run("git submodule update --init --recursive", cwd=frida_dir)
    else:
        if os.path.exists(frida_dir):
            ok(f"Using existing source at {frida_dir}")
        else:
            err(f"Source not found at {frida_dir}")
            sys.exit(1)

    # ── 应用 patches ──
    for arc in arch.split(","):
        arc = arc.strip()

    phase1_global_patches(frida_dir, name, name_cap)
    phase2_targeted_patches(frida_dir, name)

    if extended:
        phase25_extended_patches(frida_dir, name)

    if port:
        patch_port(frida_dir, port)

    if args.skip_build:
        info("--skip-build: patches applied, skipping compilation")
        return

    # ── 构建 ──
    for arc in arch.split(","):
        arc = arc.strip()
        hdr(f"Building for {arc}")
        src_binary = build_frida16(frida_dir, arc, ndk_path, output_dir)
        out_path = collect_artifacts(src_binary, name, version, arc, output_dir)

        if args.verify:
            verify_binary(out_path)

    hdr("Build complete")
    info(f"Artifacts in: {output_dir}")
    for f in os.listdir(output_dir):
        info(f"  {f}")

if __name__ == "__main__":
    main()
