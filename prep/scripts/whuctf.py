#!/usr/bin/env python3
"""WHUCTF 输入归档、静态分诊、双文件结构验收；不自动执行题目附件。"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

PREP = Path(__file__).resolve().parents[1]
ROOT = PREP.parent
PROFILE = json.loads((PREP / "whuctf-profile.json").read_text())
SECTIONS = ["初步观察与分析路线", "逐步分析与解题", "完整 flag"]
KINDS = {"original_checker", "reconstructed_checker", "remote_response", "platform_accepted"}


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def valid_flag(value):
    prefixes = "|".join(re.escape(x) for x in PROFILE["flag_prefixes"])
    return (not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and bool(re.fullmatch(rf"(?:{prefixes})\{{[^{{}}]+\}}", value)))


def init(args):
    name = args.name
    if not name or name in {".", ".."} or re.search(r"[/\\\x00-\x1f]", name):
        raise ValueError("题目名称必须是单一目录名")
    # 先检查所有输入，避免输入错误留下半个题目目录。
    attachments = [x.resolve(strict=True) for x in args.attachment]
    for p in attachments:
        if not p.is_file():
            raise ValueError(f"附件必须是文件: {p}")
    description = (args.description_file.read_text() if args.description_file else "题面尚未提供。\n")
    dest = args.root.resolve() / name
    if dest.exists():
        raise ValueError(f"题目目录已存在，保留现有内容: {dest}")
    dest.mkdir(parents=True)
    for d in ("original", "work", "evidence"):
        (dest / d).mkdir()
    (dest / "description.md").write_text(description)
    manifest = {"name": name, "created_at": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
                "urls": args.url, "status": "in_progress", "files": []}
    for n, src in enumerate(attachments):
        target = dest / "original" / f"{n:02d}-{src.name}"
        shutil.copy2(src, target)
        digest = sha256(src)
        if sha256(target) != digest:
            raise ValueError("原件复制hash不一致")
        shutil.copy2(target, dest / "work" / target.name)
        manifest["files"].append({"source": str(src), "archived": str(target.relative_to(dest)),
                                  "sha256": digest, "size": target.stat().st_size})
    write_json(dest / "manifest.json", manifest)
    (dest / "notes.md").write_text("# 过程记录\n\n## 观察与假设\n\n## 命令、输入、输出、退出码\n\n## 反证与路线调整\n\n## 候选与验证\n")
    template = (PREP / "templates/WP.template.md").read_text().replace("{{题目名称}}", name)
    (dest / "WP.md").write_text(template)
    # 真旗确认前不创建flag.txt。
    print(f"INITIALIZED={dest}")


def classify(path, info):
    low = info.lower()
    suffix = path.suffix.lower()
    if any(x in low for x in ("elf", "mach-o", "pe32", "ms-dos executable")):
        return "reverse/pwn：依输入约束及服务行为区分"
    if suffix in {".apk", ".dex", ".wasm", ".pyc", ".class"}:
        return "reverse"
    if suffix in {".pcap", ".pcapng", ".evtx", ".e01"}:
        return "forensics/misc"
    if suffix in {".php", ".js", ".html", ".ts"}:
        return "web/reverse：依执行位置判断"
    if any(x in low for x in ("image", "audio", "archive", "compressed")):
        return "misc/forensics：先检查容器与结构"
    return "待结合题面与内容分类"


def triage(args):
    root = args.challenge.resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text())
    report = []
    for item in manifest["files"]:
        p = (root / item["archived"]).resolve(strict=True)
        if not p.is_relative_to(root / "original"):
            raise ValueError("归档路径不在original目录")
        digest = sha256(p)
        if digest != item["sha256"]:
            raise ValueError(f"原件hash发生变化: {p.name}")
        cmd = ["file", "-b", "--", str(p)]
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
        info = result.stdout.strip()
        with p.open("rb") as f:
            header_hex = f.read(32).hex()
        row = {"path": item["archived"], "sha256": digest, "file_command": cmd,
               "file_output": info, "file_exit": result.returncode,
               "header_hex": header_hex, "category_hint": classify(p, info)}
        report.append(row)
    write_json(root / "evidence/triage.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def delivery_errors(root):
    root = root.resolve(strict=True)
    errors = []
    flag_path, wp_path = root / "flag.txt", root / "WP.md"
    if not flag_path.is_file() or not wp_path.is_file():
        return ["缺少flag.txt或WP.md"]
    raw = flag_path.read_text()
    flag = raw[:-1] if raw.endswith("\n") else raw
    if not valid_flag(flag):
        errors.append("flag格式、行数或控制字符不符合约定")
    wp = wp_path.read_text()
    prose_wp = re.sub(r"^```[^\n]*\n.*?^```[ \t]*$", "", wp, flags=re.S | re.M)
    headings = re.findall(r"^##[ \t]+(.+)$", prose_wp, re.M)
    sections = re.findall(r"^##[ \t]+(\d+)\.[ \t]+(.+?)[ \t]*$", prose_wp, re.M)
    titles = [title for _, title in sections]
    if len(sections) != len(headings) or [int(n) for n, _ in sections] != list(range(1, len(sections) + 1)):
        errors.append("WP章节须从1开始顺序编号，末节编号随正文变化")
    for title in SECTIONS:
        if title not in titles:
            errors.append(f"缺少章节: {title}")
    if not titles or titles[0] != SECTIONS[0] or titles[-1] != SECTIONS[-1]:
        errors.append("WP须从初步观察开始，以完整 flag结束")
    if any(t in {"题目与目标", "环境与原始证据", "失败尝试与路线调整", "最终复现", "Flag 与验证", "参考资料"}
           or t.startswith("附录") for t in headings + titles):
        errors.append("WP含已取消的前言、补充章节或附录")
    flag_section = re.search(r"^##[ \t]+\d+\.[ \t]+完整 flag[ \t]*\n(.*)\Z", wp, re.S | re.M)
    if flag_section and flag_section.group(1).strip() not in {flag, f"```text\n{flag}\n```", f"```\n{flag}\n```"}:
        errors.append("完整 flag末节只放完整flag，其后立即结束")
    if re.search(r"\{\{.*?\}\}|\bTODO\b|\bTBD\b", wp):
        errors.append("WP残留模板占位符")
    if flag and flag not in wp:
        errors.append("WP未包含本次flag")
    if len(re.findall(r"^```", wp, re.M)) % 2:
        errors.append("代码块未闭合")
    for title in ("初步观察与分析路线", "逐步分析与解题"):
        match = re.search(rf"^##\s+\d+\.\s+{title}\s*\n(.*?)(?=^##\s|\Z)", wp, re.S | re.M)
        if match:
            prose = re.sub(r"```.*?```", "", match.group(1), flags=re.S)
            if len(re.sub(r"\s+", "", prose)) < 45:
                errors.append(f"{title}正文过少，检查是否只贴脚本")
    evidence = root / "evidence/validation.json"
    if not evidence.is_file():
        errors.append("缺少验证记录evidence/validation.json")
    else:
        try:
            record = json.loads(evidence.read_text())
            if record.get("kind") not in KINDS:
                errors.append("验证类型未区分")
            if record.get("exit_status") != 0 or record.get("accepted") is not True:
                errors.append("验证未记录为通过")
            if not record.get("command") or "input" not in record:
                errors.append("验证缺少精确命令或输入")
            output = (root / record["output_file"]).resolve(strict=True)
            if not output.is_relative_to(root):
                raise ValueError("证据路径越出题目目录")
            if sha256(output) != record["output_sha256"]:
                errors.append("验证输出hash与记录不符")
            if flag.encode() not in output.read_bytes():
                errors.append("flag未出现在所引用的验证输出中")
        except (KeyError, ValueError, OSError) as e:
            errors.append(f"验证记录错误: {e}")
    manifest_path = root / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text())
        for item in manifest.get("files", []):
            p = (root / item["archived"]).resolve(strict=True)
            if not p.is_relative_to(root / "original") or sha256(p) != item["sha256"]:
                errors.append("原件hash或归档路径不符")
    return errors


def check(args):
    errors = delivery_errors(args.challenge.resolve(strict=True))
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1
    print("PASS: flag.txt + WP.md; 结构与引用证据检查通过，语义正确性由实际复现确认")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("init")
    n.add_argument("--name", required=True)
    n.add_argument("--root", type=Path, default=ROOT / "challenges")
    n.add_argument("--description-file", type=Path)
    n.add_argument("--attachment", type=Path, action="append", default=[])
    n.add_argument("--url", action="append", default=[])
    n.set_defaults(func=init)
    for command, fn in (("triage", triage), ("check", check)):
        s = sub.add_parser(command)
        s.add_argument("challenge", type=Path)
        s.set_defaults(func=fn)
    args = p.parse_args()
    try:
        return args.func(args) or 0
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
