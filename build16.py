#!/usr/bin/env python3
"""
build16.py - frida 16.x compatible build script
"""

import argparse
import os
import sys
import subprocess
import shutil
import glob
import re
import gzip
from pathlib import Path


def ok(msg):   print(f"[OK]   {msg}")
def info(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN]  {msg}")
def err(msg):  print(f"[ERROR] {msg}")
def hdr(msg):  print(f"[HEADER] {'='*60}\n[HEADER] {msg}\n[HEADER] {'='*60}")


def parse_args():
    p = argparse.ArgumentParser()
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


def run(cmd, cwd=None, env=None, check=True):
    info(f"$ {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd, env=env,
                            stdout=sys.stdout, stderr=sys.stderr)
    if check and result.returncode != 0:
        err(f"Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    return result.returncode


def replace_in_files(root, old, new):
    total = 0
    for path in Path(root).rglob("*"):
        if path.is_file() and ".git" not in str(path):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                if old in text:
                    new_text = text.replace(old, new)
                    path.write_text(new_text, encoding="utf-8")
                    total += text.count(old)
            except Exception:
                pass
    return total


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


def phase1_global_patches(frida_dir, name):
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
        ('"/frida-"',                f'"/{name}-"'),
        ("'frida-agent'",            f"'{name}-agent'"),
        ('"frida-agent"',            f'"{name}-agent"'),
        ("frida-agent-",             f"{name}-agent-"),
        ("get_frida_agent_",         f"get_{name}_agent_"),
        ("'FridaAgent'",             f"'{name_cap}Agent'"),
        ('"gum-js-loop"',            f'"{name}-js-loop"'),
        ("'frida'",                  f"'{name}'"),
    ]

    for old, new in patches:
        cnt = replace_in_files(frida_dir, old, new)
        if cnt:
            ok(f"  {old} -> {new} ({cnt})")
        else:
            warn(f"  {old} -> (not found)")

    cnt  = rename_files(frida_dir, "frida-agent",  f"{name}-agent")
    cnt += rename_files(frida_dir, "frida-helper", f"{name}-helper")
    cnt += rename_files(frida_dir, "frida-server", f"{name}-server")
    ok(f"Renamed {cnt} files on disk")
    ok("Global source patches complete")


def phase2_targeted_patches(frida_dir, name):
    hdr("PHASE 2: Targeted file patches")
    for old, new in [
        ('"frida_file"',  f'"{name}_file"'),
        ('"frida_memfd"', f'"{name}_memfd"'),
        (":frida_file",   f":{name}_file"),
        (":frida_memfd",  f":{name}_memfd"),
    ]:
        cnt = replace_in_files(frida_dir, old, new)
        if cnt:
            ok(f"  SELinux: {old} -> {new} ({cnt})")
    ok("Targeted patches complete")


def phase25_extended_patches(frida_dir, name):
    hdr("PHASE 2.5: Extended anti-detection patches")
    name_cap = name.capitalize()
    for old, new in [
        ("FridaGadget", f"{name_cap}Gadget"),
        ("FridaPortal",  f"{name_cap}Portal"),
        ("FridaInject",  f"{name_cap}Inject"),
        ('".frida"',     f'".{name}"'),
        ('"frida-"',     f'"{name}-"'),
    ]:
        cnt = replace_in_files(frida_dir, old, new)
        if cnt:
            ok(f"  {old} -> {new} ({cnt})")
        else:
            warn(f"  {old} -> (not found)")
    ok("Extended patches complete")


def patch_port(frida_dir, port):
    if not port:
        return
    info(f"Patching default port 27042 -> {port}")
    cnt = replace_in_files(frida_dir, "27042", str(port))
    ok(f"Port patched ({cnt} occurrences)")


def patch_ndk_version_check(frida_dir, ndk_path):
    setup_env = os.path.join(frida_dir, "releng", "setup-env.sh")
    if not os.path.exists(setup_env):
        warn("releng/setup-env.sh not found, skipping NDK version patch")
        return

    # 获取实际 NDK 版本号
    ndk_abs = os.path.abspath(ndk_path)
    ndk_dir_name = os.path.basename(ndk_abs)
    m = re.search(r'(r\d+[a-z]*)', ndk_dir_name, re.IGNORECASE)
    actual_ver = m.group(1).lower() if m else "r25c"

    with open(setup_env, "r") as f:
        content = f.read()

    modified = False

    # 修复1：把 #!/bin/sh 改成 #!/bin/bash，解决 bash 语法不兼容问题
    if content.startswith("#!/bin/sh"):
        content = "#!/bin/bash" + content[len("#!/bin/sh"):]
        ok("Patched setup-env.sh: #!/bin/sh -> #!/bin/bash")
        modified = True

    # 修复2：替换 ndk_required 变量值（多种格式）
    patterns = [
        (r'ndk_required="r\d+[a-z]*"',   f'ndk_required="{actual_ver}"'),
        (r"ndk_required='r\d+[a-z]*'",   f"ndk_required='{actual_ver}'"),
        (r'ndk_required=r\d+[a-z]*\b',   f'ndk_required={actual_ver}'),
    ]
    for pattern, replacement in patterns:
        new_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        if new_content != content:
            content = new_content
            ok(f"Patched setup-env.sh: ndk_required -> {actual_ver}")
            modified = True
            break

    # 修复3：如果还是没找到，直接在文件头部插入覆盖变量
    if not modified or 'ndk_required' not in content:
        # 在 shebang 之后第一行插入
        lines = content.split('\n')
        insert_idx = 1
        for i, line in enumerate(lines):
            if line.startswith('#!'):
                insert_idx = i + 1
                break
        lines.insert(insert_idx, f'\n# NDK version override by build16.py\nndk_required={actual_ver}\n')
        content = '\n'.join(lines)
        ok(f"Injected ndk_required={actual_ver} into setup-env.sh")
        modified = True

    # 修复4：注释掉 NDK 版本不匹配时的 exit 1
    # 找到类似 "Unsupported NDK version" 后面的 exit 1
    content = re.sub(
        r'(echo.*[Uu]nsupported NDK.*\n)',
        r'# \1',
        content
    )
    content = re.sub(
        r'(echo.*NDK.*[Pp]lease install.*\n)',
        r'# \1',
        content
    )

    with open(setup_env, "w") as f:
        f.write(content)

    if modified:
        ok(f"setup-env.sh patched successfully (NDK={actual_ver}, bash mode)")
    else:
        warn("setup-env.sh: no changes made")


def build_frida16(frida_dir, arch, ndk_path, output_dir):
    hdr(f"Building for {arch}")

    arch_map = {
        "android-arm64":  "arm64",
        "android-arm":    "arm",
        "android-x86_64": "x86_64",
        "android-x86":    "x86",
    }
    make_arch = arch_map.get(arch, "arm64")

    env = os.environ.copy()
    if ndk_path:
        ndk_abs = os.path.abspath(ndk_path)
        env["ANDROID_NDK_ROOT"] = ndk_abs
        env["ANDROID_NDK_HOME"] = ndk_abs
        info(f"NDK: {ndk_abs}")

    targets = [
        f"server-android-{make_arch}",
        f"core-android-{make_arch}",
    ]

    success = False
    for target in targets:
        info(f"Trying make target: {target}")
        rc = run(f"make {target}", cwd=frida_dir, env=env, check=False)
        if rc == 0:
            ok(f"Build succeeded with target: {target}")
            success = True
            break
        warn(f"make {target} failed (rc={rc}), trying next...")

    if not success:
        err("All make targets failed!")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    search_patterns = [
        f"build/frida-android-{make_arch}/bin/frida-server",
        f"build/frida_thin-android-{make_arch}/bin/frida-server",
        f"build/tmp-android-{make_arch}/frida-server",
        f"build/tmp_thin-android-{make_arch}/frida-server",
    ]

    src = None
    for pattern in search_patterns:
        matches = glob.glob(os.path.join(frida_dir, pattern))
        if matches:
            src = matches[0]
            ok(f"Found binary: {src}")
            break

    if src is None:
        warn("Searching recursively for server binary...")
        for p in Path(frida_dir).rglob("frida-server"):
            if p.is_file() and ".git" not in str(p) and "build" in str(p):
                src = str(p)
                ok(f"Found: {src}")
                break

    if src is None:
        err("Could not find built frida-server binary!")
        build_dir = os.path.join(frida_dir, "build")
        if os.path.exists(build_dir):
            info("Contents of build/:")
            for item in os.listdir(build_dir):
                info(f"  {item}")
        sys.exit(1)

    return src


def collect_artifacts(src_binary, name, version, arch, output_dir):
    hdr("Collecting artifacts")
    os.makedirs(output_dir, exist_ok=True)

    out_name = f"{name}-server-{version}-{arch}"
    out_path = os.path.join(output_dir, out_name)
    shutil.copy2(src_binary, out_path)
    ok(f"Copied: {out_name}")

    gz_path = out_path + ".gz"
    with open(out_path, "rb") as f_in:
        with gzip.open(gz_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    ok(f"Compressed: {out_name}.gz")

    return out_path


def verify_binary(binary_path):
    hdr("Binary verification")
    result = subprocess.run(["strings", binary_path], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    frida_lines = [l for l in lines if "frida" in l.lower()]
    if frida_lines:
        warn(f"Found {len(frida_lines)} residual 'frida' strings:")
        for l in frida_lines[:20]:
            warn(f"  {l}")
    else:
        ok("No residual 'frida' strings found!")


def main():
    args = parse_args()

    version    = args.version
    name       = args.name.lower()
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

    if not args.skip_clone:
        if os.path.exists(frida_dir):
            shutil.rmtree(frida_dir)
        hdr("Cloning Frida source")
        run(f"git clone --branch {version} --depth 1 "
            f"https://github.com/frida/frida.git {frida_dir}")
        run("git submodule update --init --recursive", cwd=frida_dir)
    else:
        if os.path.exists(frida_dir):
            ok(f"Using existing source at {frida_dir}")
        else:
            err(f"Source not found at {frida_dir}")
            sys.exit(1)

    # NDK 修复必须在 phase1 字符串替换之前执行
    # 否则 setup-env.sh 被替换后正则匹配失败
    if ndk_path:
        hdr("PRE-PATCH: Fix NDK version check")
        patch_ndk_version_check(frida_dir, ndk_path)

    phase1_global_patches(frida_dir, name)
    phase2_targeted_patches(frida_dir, name)

    if extended:
        phase25_extended_patches(frida_dir, name)

    if port:
        patch_port(frida_dir, port)

    if args.skip_build:
        info("--skip-build: patches applied, skipping compilation")
        return

    for arc in arch.split(","):
        arc = arc.strip()
        src_binary = build_frida16(frida_dir, arc, ndk_path, output_dir)
        out_path = collect_artifacts(src_binary, name, version, arc, output_dir)
        if args.verify:
            verify_binary(out_path)

    hdr("Build complete")
    info(f"Artifacts in: {output_dir}")
    for f in sorted(os.listdir(output_dir)):
        info(f"  {f}")


if __name__ == "__main__":
    main()
