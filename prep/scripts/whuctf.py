#!/usr/bin/env python3
"""WHUCTF 输入归档、静态分诊和交付结构检查。

只处理题面与用户明确指定的本地附件路径：不执行附件、不连接题目服务、不提交 flag。
triage 至多调用系统 file 读取类型描述；找不到 file 时只记录文件头和扩展名提示。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

PREP = Path(__file__).resolve().parents[1]
ROOT = PREP.parent
PROFILE_PATH = PREP / "whuctf-profile.json"
TEMPLATE_PATH = PREP / "templates" / "WP.template.md"
SECTIONS = ["初步观察与分析路线", "逐步分析与解题", "完整 flag"]
KINDS = {"original_checker", "reconstructed_checker", "remote_response", "platform_accepted"}
GENERIC = "待结合题面与内容分类"
CANCELLED_TITLES = {
    "题目与目标",
    "环境与原始证据",
    "失败尝试与路线调整",
    "最终复现",
    "Flag 与验证",
    "参考资料",
}
NOTES = (
    "# 过程记录\n\n"
    "## 观察与假设\n\n"
    "## 命令、输入、输出、退出码\n\n"
    "## 反证与路线调整\n\n"
    "## 候选与验证\n"
)
_NAME_INVALID = re.compile(r'[\x00-\x1f\x7f<>:"|?*\\/]')
_FENCE = re.compile(r"^```[^\n]*\n.*?^```[ \t]*$", re.S | re.M)
_MAX_NAME_BYTES = 255
_FILE_TIMEOUT_SECONDS = 10
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "MS-DOS executable PE32"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\x00asm", "wasm"),
    (b"PK\x03\x04", "archive compressed"),
    (b"PK\x05\x06", "archive compressed"),
    (b"PK\x07\x08", "archive compressed"),
    (b"\x1f\x8b", "compressed"),
    (b"\x89PNG\r\n\x1a\n", "image"),
    (b"\xff\xd8\xff", "image"),
    (b"GIF87a", "image"),
    (b"GIF89a", "image"),
    (b"ID3", "audio"),
    (b"OggS", "audio"),
    (b"fLaC", "audio"),
)


def load_profile(path: Path) -> dict[str, Any]:
    """读取工作流配置。CLI 只强制校验 flag_prefixes。"""
    config_path = Path(path)
    try:
        raw = config_path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise ValueError(f"配置必须是 UTF-8 文本: {config_path}") from exc
    except OSError as exc:
        raise ValueError(f"无法读取配置: {config_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"配置不是合法 JSON: {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("配置必须是 JSON 对象")
    prefixes = data.get("flag_prefixes")
    if not isinstance(prefixes, list) or not prefixes or not all(_valid_prefix(item) for item in prefixes):
        raise ValueError("flag_prefixes 必须是非空的前缀列表，且不能包含空白、控制字符或花括号")
    return data


def _valid_prefix(item: object) -> bool:
    return (
        isinstance(item, str)
        and bool(item)
        and not any(ord(char) < 32 or ord(char) == 127 or char in "{} \t" for char in item)
    )


PROFILE = load_profile(PROFILE_PATH)


def read_text(path: Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    """按 UTF-8 和 LF 写入，避免题目文件随系统换行设置变化。"""
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def sha256(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path | str, value: Any) -> None:
    write_text(Path(path), json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def local_tz() -> ZoneInfo | timezone:
    """优先用 Asia/Shanghai；没有时区数据时退回固定的 UTC+8。"""
    try:
        return ZoneInfo("Asia/Shanghai")
    except ZoneInfoNotFoundError:
        return timezone(timedelta(hours=8))


def valid_flag(value: str) -> bool:
    """flag 形如 prefix{body}。本函数不修剪空白或换行。"""
    if not isinstance(value, str):
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    prefixes = PROFILE.get("flag_prefixes") if isinstance(PROFILE, dict) else None
    if not isinstance(prefixes, list) or not all(isinstance(item, str) and item for item in prefixes):
        return False
    pattern = "|".join(re.escape(item) for item in prefixes)
    return re.fullmatch(rf"(?:{pattern})\{{[^{{}}]+\}}", value) is not None


def validate_challenge_name(name: object) -> str:
    if not isinstance(name, str):
        raise ValueError("题目名称必须是单一目录名")
    if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
        raise ValueError("题目名称过长")
    if not name or name in {".", ".."} or name != name.strip() or name.endswith(".") or _NAME_INVALID.search(name):
        raise ValueError("题目名称必须是单一目录名")
    return name


def resolve_attachment(path: Path) -> Path:
    try:
        resolved = Path(path).resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"附件不存在: {path}") from exc
    except OSError as exc:
        raise ValueError(f"附件无法读取: {path}: {exc}") from exc
    try:
        info = resolved.stat()
    except OSError as exc:
        raise ValueError(f"附件无法读取: {path}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"附件必须是文件: {resolved}")
    if not resolved.name or resolved.name in {".", ".."} or re.search(r"[\x00-\x1f\x7f]", resolved.name):
        raise ValueError(f"附件文件名不合法: {resolved.name!r}")
    return resolved


def validate_urls(urls: Optional[Sequence[object]]) -> list[str]:
    if not urls:
        return []
    cleaned: list[str] = []
    for url in urls:
        if not isinstance(url, str) or not url or any(ord(char) < 32 or ord(char) == 127 for char in url):
            raise ValueError(f"题目 URL 不合法: {url!r}")
        cleaned.append(url)
    return cleaned


def resolve_challenge(path: Path) -> Path:
    try:
        resolved = Path(path).resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"题目目录不存在: {path}") from exc
    except OSError as exc:
        raise ValueError(f"题目目录无法读取: {path}: {exc}") from exc
    if not resolved.is_dir():
        raise ValueError(f"题目路径必须是目录: {resolved}")
    return resolved


def locate_original(root: Path, archived: object) -> Path:
    """定位 original/ 下的普通文件。不跟随符号链接，也不接受绝对路径或 ..。"""
    if not isinstance(archived, str) or not archived:
        raise ValueError("归档路径不在original目录")
    relative = Path(archived)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.parts
        or relative.parts[0] != "original"
    ):
        raise ValueError("归档路径不在original目录")
    original = root / "original"
    if not original.exists() and not original.is_symlink():
        raise ValueError(f"归档文件不存在: {archived}")
    if original.is_symlink() or not original.is_dir():
        raise ValueError("归档路径不在original目录")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("归档路径不在original目录")
        if not current.exists():
            raise ValueError(f"归档文件不存在: {archived}")
    if not current.is_file() or not stat.S_ISREG(current.stat().st_mode):
        raise ValueError("归档路径不在original目录")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(original.resolve()):
        raise ValueError("归档路径不在original目录")
    return current


def init(args: Any) -> None:
    """归档题面和附件。先校验全部输入，再用同盘临时目录提交，失败时不留半成品。"""
    name = validate_challenge_name(getattr(args, "name", None))
    attachments = [resolve_attachment(item) for item in (getattr(args, "attachment", None) or [])]
    for index, src in enumerate(attachments):
        if len(f"{index:02d}-{src.name}".encode("utf-8")) > _MAX_NAME_BYTES:
            raise ValueError(f"附件文件名过长: {src.name}")
    description = _read_description(getattr(args, "description_file", None))
    urls = validate_urls(getattr(args, "url", None))
    if not TEMPLATE_PATH.is_file():
        raise ValueError(f"缺少 WP 模板: {TEMPLATE_PATH}")
    template = read_text(TEMPLATE_PATH).replace("{{题目名称}}", name)
    root_dir = Path(args.root).resolve()
    dest = root_dir / name
    if dest.exists():
        raise ValueError(f"题目目录已存在，保留现有内容: {dest}")
    root_dir.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise ValueError(f"题目目录已存在，保留现有内容: {dest}")
    staging = Path(tempfile.mkdtemp(prefix=".init-", dir=root_dir))
    try:
        _populate(staging, name, attachments, description, urls, template)
        try:
            staging.rename(dest)
        except FileExistsError as exc:
            raise ValueError(f"题目目录已存在，保留现有内容: {dest}") from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"INITIALIZED={dest}")


def _read_description(path: Optional[Path]) -> str:
    if path is None:
        return "题面尚未提供。\n"
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError(f"题面文件不存在: {file_path}")
    if not file_path.is_file() or not stat.S_ISREG(file_path.stat().st_mode):
        raise ValueError(f"题面路径必须是文件: {file_path}")
    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise ValueError(f"题面文件必须是 UTF-8 文本: {file_path}") from exc
    except OSError as exc:
        raise ValueError(f"题面文件无法读取: {file_path}: {exc}") from exc


def _populate(
    staging: Path,
    name: str,
    attachments: Sequence[Path],
    description: str,
    urls: Sequence[str],
    template: str,
) -> None:
    for directory in ("original", "work", "evidence"):
        (staging / directory).mkdir()
    write_text(staging / "description.md", description)
    manifest: dict[str, Any] = {
        "name": name,
        "created_at": datetime.now(local_tz()).isoformat(),
        "urls": list(urls),
        "status": "in_progress",
        "files": [],
    }
    for index, src in enumerate(attachments):
        target = staging / "original" / f"{index:02d}-{src.name}"
        digest = sha256(src)
        shutil.copy2(src, target)
        if sha256(target) != digest:
            raise ValueError("原件复制hash不一致")
        work_copy = staging / "work" / target.name
        shutil.copy2(target, work_copy)
        if sha256(work_copy) != digest:
            raise ValueError("原件复制hash不一致")
        manifest["files"].append(
            {
                "source": str(src),
                "archived": str(target.relative_to(staging)),
                "sha256": digest,
                "size": target.stat().st_size,
            }
        )
    write_json(staging / "manifest.json", manifest)
    write_text(staging / "notes.md", NOTES)
    write_text(staging / "WP.md", template)


def magic_hint(header: bytes) -> str:
    """file 没有输出时使用的文件头提示，词表与 classify 已有关键字对齐。"""
    for signature, label in _MAGIC:
        if header.startswith(signature):
            return label
    return ""


def classify(path: Path, info: str) -> str:
    """给出分诊提示。内容关键字优先于容易误导的后缀；结果不参与 check。"""
    low = info.lower()
    suffix = Path(path).suffix.lower()
    if any(token in low for token in ("elf", "mach-o", "pe32", "ms-dos executable")):
        return "reverse/pwn：依输入约束及服务行为区分"
    if suffix in {".apk", ".dex", ".wasm", ".pyc", ".class"} or "wasm" in low:
        return "reverse"
    if suffix in {".pcap", ".pcapng", ".evtx", ".e01"}:
        return "forensics/misc"
    if any(token in low for token in ("image", "audio", "archive", "compressed")):
        return "misc/forensics：先检查容器与结构"
    if suffix == ".ts" and any(token in low for token in ("mpeg", "transport stream", "mp2t")):
        return "misc/forensics：先检查容器与结构"
    if suffix in {".php", ".js", ".html", ".ts"}:
        return "web/reverse：依执行位置判断"
    return GENERIC


def triage(args: Any) -> None:
    root = resolve_challenge(args.challenge)
    manifest = _read_manifest(root)
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("manifest.json 缺少 files 数组")
    file_available = True
    if files:
        file_available = shutil.which("file") is not None
        if not file_available:
            print("WARNING: 未找到 file 命令，仅根据扩展名和文件头给出分类提示", file=sys.stderr)
    report = []
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("archived"), str) or not isinstance(item.get("sha256"), str):
            raise ValueError("manifest.json 文件条目缺少 archived 或 sha256")
        archived = locate_original(root, item["archived"])
        digest = sha256(archived)
        if digest != item["sha256"]:
            raise ValueError(f"原件hash发生变化: {archived.name}")
        command, info, exit_code = _run_file(archived, file_available)
        with archived.open("rb") as handle:
            header = handle.read(32)
        hint_info = info if info else magic_hint(header)
        report.append(
            {
                "path": item["archived"],
                "sha256": digest,
                "file_command": command,
                "file_output": info,
                "file_exit": exit_code,
                "header_hex": header.hex(),
                "category_hint": classify(archived, hint_info),
            }
        )
    (root / "evidence").mkdir(exist_ok=True)
    write_json(root / "evidence" / "triage.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def _read_manifest(root: Path) -> dict[str, Any]:
    path = root / "manifest.json"
    if not path.is_file():
        raise ValueError(f"缺少 manifest.json: {root}")
    try:
        data = json.loads(read_text(path))
    except UnicodeError as exc:
        raise ValueError(f"manifest.json 无法解析: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest.json 无法解析: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"缺少 manifest.json: {root}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("manifest.json 缺少 files 数组")
    return data


def _run_file(path: Path, file_available: bool) -> tuple[list[str], str, Optional[int]]:
    command = ["file", "-b", "--", str(path)]
    if not file_available:
        return command, "", None
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=_FILE_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except FileNotFoundError:
        return command, "", None
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"file 命令超时: {path.name}") from exc
    return command, (result.stdout or "").strip(), int(result.returncode)


def delivery_errors(root: Path) -> list[str]:
    root = resolve_challenge(root)
    flag_path = root / "flag.txt"
    wp_path = root / "WP.md"
    if not flag_path.is_file() or not wp_path.is_file():
        return ["缺少flag.txt或WP.md"]
    try:
        # universal newlines 会把 CRLF/CR 译成 LF，下面只去掉至多一个结尾换行。
        raw = flag_path.read_text(encoding="utf-8")
        wp = wp_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"无法读取 flag.txt 或 WP.md: {exc}"]
    flag = raw[:-1] if raw.endswith("\n") else raw
    errors: list[str] = []
    if not valid_flag(flag):
        errors.append("flag格式、行数或控制字符不符合约定")
    prose_wp = _FENCE.sub("", wp)
    headings = re.findall(r"^##[ \t]+(.+)$", prose_wp, re.M)
    sections = re.findall(r"^##[ \t]+(\d+)\.[ \t]+(.+?)[ \t]*$", prose_wp, re.M)
    titles = [title for _, title in sections]
    if len(sections) != len(headings) or [int(number) for number, _ in sections] != list(range(1, len(sections) + 1)):
        errors.append("WP章节须从1开始顺序编号，末节编号随正文变化")
    for title in SECTIONS:
        if title not in titles:
            errors.append(f"缺少章节: {title}")
    if not titles or titles[0] != SECTIONS[0] or titles[-1] != SECTIONS[-1]:
        errors.append("WP须从初步观察开始，以完整 flag结束")
    if any(item in CANCELLED_TITLES or item.startswith("附录") for item in headings + titles):
        errors.append("WP含已取消的前言、补充章节或附录")
    flag_section = re.search(r"^##[ \t]+\d+\.[ \t]+完整 flag[ \t]*(?:\n(.*))?\Z", wp, re.S | re.M)
    if flag_section is not None:
        flag_body = flag_section.group(1) or ""
        if flag_body.strip() not in {flag, f"```text\n{flag}\n```", f"```\n{flag}\n```"}:
            errors.append("完整 flag末节只放完整flag，其后立即结束")
    if re.search(r"\{\{.*?\}\}|\bTODO\b|\bTBD\b", wp):
        errors.append("WP残留模板占位符")
    if flag and flag not in wp:
        errors.append("WP未包含本次flag")
    if len(re.findall(r"^```", wp, re.M)) % 2:
        errors.append("代码块未闭合")
    for title in ("初步观察与分析路线", "逐步分析与解题"):
        match = re.search(rf"^##\s+\d+\.\s+{re.escape(title)}\s*\n(.*?)(?=^##\s|\Z)", prose_wp, re.S | re.M)
        if match and len(re.sub(r"\s+", "", re.sub(r"```.*?```", "", match.group(1), flags=re.S))) < 45:
            errors.append(f"{title}正文过少，检查是否只贴脚本")
    errors.extend(_validation_errors(root, flag))
    errors.extend(_manifest_problems(root))
    return errors


def _validation_errors(root: Path, flag: str) -> list[str]:
    evidence = root / "evidence" / "validation.json"
    if not evidence.is_file():
        return ["缺少验证记录evidence/validation.json"]
    errors: list[str] = []
    try:
        record = json.loads(read_text(evidence))
        if not isinstance(record, dict):
            raise ValueError("validation.json 必须是对象")
        if record.get("kind") not in KINDS:
            errors.append("验证类型未区分")
        if record.get("exit_status") != 0 or record.get("accepted") is not True:
            errors.append("验证未记录为通过")
        if not record.get("command") or "input" not in record:
            errors.append("验证缺少精确命令或输入")
        output = _validation_output(root, record["output_file"])
        if sha256(output) != record["output_sha256"]:
            errors.append("验证输出hash与记录不符")
        if flag.encode("utf-8") not in output.read_bytes():
            errors.append("flag未出现在所引用的验证输出中")
    except (KeyError, ValueError, OSError, UnicodeError) as exc:
        errors.append(f"验证记录错误: {exc}")
    return errors


def _validation_output(root: Path, output_field: object) -> Path:
    if not isinstance(output_field, str) or not output_field:
        raise ValueError("验证输出路径缺失")
    candidate = Path(output_field)
    if not candidate.is_absolute() and ".." in candidate.parts:
        raise ValueError("证据路径越出题目目录")
    output = candidate if candidate.is_absolute() else root / candidate
    try:
        info = output.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"引用的验证输出不存在: {output_field}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("证据路径越出题目目录")
    resolved = output.resolve(strict=True)
    if not resolved.is_file() or not resolved.is_relative_to(root):
        raise ValueError("证据路径越出题目目录")
    return resolved


def _manifest_problems(root: Path) -> list[str]:
    path = root / "manifest.json"
    if not path.is_file():
        return []
    try:
        manifest = json.loads(read_text(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"manifest.json 无法读取: {exc}"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        return ["manifest.json 缺少 files 数组"]
    problems = []
    for item in manifest["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("archived"), str) or not isinstance(item.get("sha256"), str):
            problems.append("原件hash或归档路径不符")
            continue
        try:
            archived = locate_original(root, item["archived"])
            digest = sha256(archived)
        except (ValueError, OSError):
            problems.append("原件hash或归档路径不符")
            continue
        if digest != item["sha256"]:
            problems.append("原件hash或归档路径不符")
    return problems


def check(args: Any) -> int:
    errors = delivery_errors(args.challenge)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: flag.txt + WP.md; 结构与引用证据检查通过，语义正确性由实际复现确认")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whuctf.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "退出码：0 成功；1 结构检查未通过；2 输入或运行错误。\n"
            "示例：\n"
            "  python3 prep/scripts/whuctf.py init --name sample --description-file prompt.md --attachment challenge.bin\n"
            "  python3 prep/scripts/whuctf.py triage challenges/sample\n"
            "  python3 prep/scripts/whuctf.py check challenges/sample"
        ),
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    init_parser = subparsers.add_parser("init", help="归档题面和附件，生成工作目录与 WP 模板")
    init_parser.add_argument("--name", required=True, help="单个目录名，不含路径分隔符")
    init_parser.add_argument("--root", type=Path, default=ROOT / "challenges", help="题目根目录，默认 challenges/")
    init_parser.add_argument("--description-file", type=Path, help="UTF-8 题面文件；省略时写入占位说明")
    init_parser.add_argument("--attachment", type=Path, action="append", default=[], help="只归档不执行；可重复")
    init_parser.add_argument("--url", action="append", default=[], help="题目地址或标识；可重复")
    init_parser.set_defaults(func=init)
    for command, function, help_text in (
        ("triage", triage, "校验原件 hash，并记录 file 与文件头"),
        ("check", check, "检查 flag、WP 和验证证据的结构"),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument("challenge", type=Path, help="题目目录")
        subparser.set_defaults(func=function)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args) or 0)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
