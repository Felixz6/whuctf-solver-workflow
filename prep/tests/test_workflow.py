import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/whuctf.py"
spec = importlib.util.spec_from_file_location("whuctf", SCRIPT)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class WorkflowTest(unittest.TestCase):
    def test_allowed_prefixes(self):
        for x in ("WHUCTF{unit_fixture}", "whuctf{unit_fixture}", "flag{unit_fixture}"):
            self.assertTrue(w.valid_flag(x))

    def test_invalid_flags(self):
        for x in ("FLAG{fixture}", "mayctf{fixture}", "flag{}", "flag{x}\nflag{y}",
                  "xflag{x}", "flag{x}{y}", "flag{x\x00}", "flag{x}\n"):
            self.assertFalse(w.valid_flag(x))

    def test_init_original_and_copy(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            src = base / "source.bin"
            src.write_bytes(b"\x7fELFfixture")
            args = SimpleNamespace(name="archive", root=base / "tasks", attachment=[src],
                                   description_file=None, url=["https://example.invalid/task"])
            w.init(args)
            task = args.root / args.name
            self.assertFalse((task / "flag.txt").exists())
            wp = (task / "WP.md").read_text()
            self.assertTrue(wp.startswith("# archive\n\n## 1. 初步观察与分析路线"))
            self.assertIn("## 3. 完整利用脚本", wp)
            self.assertIn("## 4. 完整 flag", wp)
            self.assertNotIn("## 1. 题目与目标", wp)
            self.assertEqual(src.read_bytes(), (task / "original/00-source.bin").read_bytes())
            (task / "work/00-source.bin").write_bytes(b"modified")
            self.assertEqual(src.read_bytes(), (task / "original/00-source.bin").read_bytes())
            with self.assertRaises(ValueError):
                w.init(args)

    def test_reject_path_escape(self):
        with self.assertRaises(ValueError):
            w.init(SimpleNamespace(name="../escape"))

    def test_same_basename_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            a, b = root / "a", root / "b"
            a.mkdir(); b.mkdir()
            (a / "input.txt").write_text("one")
            (b / "input.txt").write_text("two")
            args = SimpleNamespace(name="collision", root=root / "tasks", attachment=[a / "input.txt", b / "input.txt"], description_file=None, url=[])
            w.init(args)
            task = args.root / args.name
            self.assertEqual((task / "original/00-input.txt").read_text(), "one")
            self.assertEqual((task / "original/01-input.txt").read_text(), "two")

    def test_triage_hash_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "sample.txt"
            source.write_text("sample")
            args = SimpleNamespace(name="triage", root=root / "tasks", attachment=[source], description_file=None, url=[])
            w.init(args)
            task = args.root / args.name
            w.triage(SimpleNamespace(challenge=task))
            self.assertTrue((task / "evidence/triage.json").is_file())
            (task / "original/00-sample.txt").write_text("tampered")
            with self.assertRaises(ValueError):
                w.triage(SimpleNamespace(challenge=task))

    def test_gate_evidence_and_wp(self):
        with tempfile.TemporaryDirectory() as d:
            task = Path(d)
            (task / "evidence").mkdir()
            # 纯测试输入，不是比赛答案。
            flag = "WHUCTF{unit_fixture}"
            (task / "flag.txt").write_text(flag + "\n")
            wp = "# 单元测试\n" + "\n".join(
                f"## {i}. {title}\n" + "这是测试样本的结构说明，真实赛题仍需按照观察、推导、操作、输出和下一步依据逐项解释并复现。" * 3
                for i, title in enumerate(w.SECTIONS[:-1], 1)) + "\n## 3. 完整 flag\n\n```text\n" + flag + "\n```\n"
            (task / "WP.md").write_text(wp)
            self.assertTrue(w.delivery_errors(task))
            out = task / "evidence/output.txt"
            out.write_text(flag + "\n")
            record = {"kind": "reconstructed_checker", "accepted": True, "exit_status": 0,
                      "command": ["unit-test-fixture"], "input": "local-fixture",
                      "output_file": "evidence/output.txt", "output_sha256": w.sha256(out)}
            (task / "evidence/validation.json").write_text(json.dumps(record))
            self.assertEqual(w.delivery_errors(task), [])
            for count in (0, 1, 3):
                middle = "".join(f"## {n}. 继续分析{n}\n这是额外的实际解题步骤。\n\n" for n in range(3, 3 + count))
                (task / "WP.md").write_text(wp.replace("## 3. 完整 flag", middle + f"## {3 + count}. 完整 flag"))
                self.assertEqual(w.delivery_errors(task), [], f"末节编号{3 + count}")
            for suffix in ("\n## 4. 参考资料\n旧内容", "\n## 附录：脚本\n代码", "\n多余的结尾说明"):
                (task / "WP.md").write_text(wp + suffix)
                self.assertTrue(w.delivery_errors(task))
            (task / "WP.md").write_text(wp.replace("## 1. 初步观察与分析路线", "## 1. 题目与目标"))
            self.assertTrue(w.delivery_errors(task))
            (task / "WP.md").write_text(wp)
            out.write_text("tampered\n")
            self.assertIn("验证输出hash与记录不符", w.delivery_errors(task))
            out.write_text(flag + "\n")
            record["accepted"] = False
            (task / "evidence/validation.json").write_text(json.dumps(record))
            self.assertIn("验证未记录为通过", w.delivery_errors(task))
            record["accepted"] = True
            record["output_file"] = "../../outside.txt"
            (task / "evidence/validation.json").write_text(json.dumps(record))
            self.assertTrue(w.delivery_errors(task))


FLAG = "WHUCTF{unit_fixture}"
BODY = "这是测试样本的结构说明，真实赛题仍需按照观察、推导、操作、输出和下一步依据逐项解释并复现。" * 3
REPO = Path(__file__).resolve().parents[2]


def init_args(name, root, attachment=None, description_file=None, url=None):
    return SimpleNamespace(
        name=name,
        root=root,
        attachment=[] if attachment is None else attachment,
        description_file=description_file,
        url=[] if url is None else url,
    )


def quiet_init(args):
    with redirect_stdout(io.StringIO()):
        w.init(args)


def write_passing(task, flag=FLAG):
    (task / "evidence").mkdir(parents=True, exist_ok=True)
    (task / "flag.txt").write_text(flag + "\n", encoding="utf-8")
    wp = (
        "# 单元测试\n"
        f"## 1. 初步观察与分析路线\n{BODY}\n"
        f"## 2. 逐步分析与解题\n{BODY}\n"
        f"## 3. 完整 flag\n\n```text\n{flag}\n```\n"
    )
    (task / "WP.md").write_text(wp, encoding="utf-8")
    output = task / "evidence" / "output.txt"
    output.write_text(flag + "\n", encoding="utf-8")
    record = {
        "kind": "reconstructed_checker",
        "accepted": True,
        "exit_status": 0,
        "command": ["unit-test-fixture"],
        "input": "local-fixture",
        "output_file": "evidence/output.txt",
        "output_sha256": w.sha256(output),
    }
    (task / "evidence" / "validation.json").write_text(json.dumps(record), encoding="utf-8")
    return record


def load_record(task):
    return json.loads((task / "evidence" / "validation.json").read_text(encoding="utf-8"))


def save_record(task, record):
    (task / "evidence" / "validation.json").write_text(json.dumps(record), encoding="utf-8")


class InitEdgeTest(unittest.TestCase):
    def test_metadata_unicode_name_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "a.bin"
            source.write_bytes(b"abc")
            description = root / "题面.md"
            description.write_text("中文题面\n", encoding="utf-8")
            args = init_args("题目 一", root / "tasks", [source], description, ["https://example.invalid/task"])
            quiet_init(args)
            task = args.root / args.name
            self.assertFalse((task / "flag.txt").exists())
            self.assertEqual((task / "description.md").read_text(encoding="utf-8"), "中文题面\n")
            self.assertTrue((task / "WP.md").read_text(encoding="utf-8").startswith("# 题目 一\n"))
            self.assertIn("## 命令、输入、输出、退出码", (task / "notes.md").read_text(encoding="utf-8"))
            self.assertNotIn(b"\r", (task / "notes.md").read_bytes())
            manifest = json.loads((task / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["urls"], ["https://example.invalid/task"])
            self.assertEqual(manifest["status"], "in_progress")
            self.assertEqual(manifest["files"][0]["archived"], "original/00-a.bin")
            self.assertEqual(manifest["files"][0]["sha256"], w.sha256(source))
            self.assertEqual(datetime.fromisoformat(manifest["created_at"]).utcoffset(), timedelta(hours=8))
            self.assertEqual((task / "work/00-a.bin").read_bytes(), source.read_bytes())

    def test_names_and_inputs_fail_before_creating_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("", ".", "..", "a/b", "a\\b", "a:b", "a?", " a", "a ", "a.", "a\nb", None):
                with self.assertRaises(ValueError):
                    w.init(SimpleNamespace(name=name))
            with self.assertRaises(ValueError) as caught:
                w.init(SimpleNamespace(name="a" * 256))
            self.assertIn("过长", str(caught.exception))
            quiet_init(init_args("a" * 255, root / "long"))
            self.assertTrue((root / "long" / ("a" * 255)).is_dir())
            quiet_init(init_args("web.sql", root / "dotted"))
            self.assertTrue((root / "dotted" / "web.sql").is_dir())

            missing = root / "missing.bin"
            with self.assertRaises(ValueError) as caught:
                w.init(init_args("t", root / "tasks", [missing]))
            self.assertIn("附件不存在", str(caught.exception))
            folder = root / "dir"
            folder.mkdir()
            with self.assertRaises(ValueError) as caught:
                w.init(init_args("t", root / "tasks", [folder]))
            self.assertIn("附件必须是文件", str(caught.exception))
            pipe = root / "pipe"
            os.mkfifo(pipe)
            with self.assertRaises(ValueError) as caught:
                w.init(init_args("t", root / "tasks", [pipe]))
            self.assertIn("附件必须是文件", str(caught.exception))
            description = root / "bad.md"
            description.write_bytes(b"\xff")
            with self.assertRaises(ValueError) as caught:
                w.init(init_args("t", root / "tasks", description_file=description))
            self.assertIn("UTF-8", str(caught.exception))
            with self.assertRaises(ValueError) as caught:
                w.init(init_args("t", root / "tasks", url=["http://example.invalid/\n"]))
            self.assertIn("URL", str(caught.exception))
            odd_name = root / "bad\nname.txt"
            odd_name.write_text("x", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                w.init(init_args("t", root / "tasks", [odd_name]))
            self.assertIn("附件文件名不合法", str(caught.exception))
            self.assertFalse((root / "tasks").exists())

    def test_failed_copy_leaves_no_partial_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "a.bin", root / "b.bin"
            first.write_bytes(b"a")
            second.write_bytes(b"b")
            args = init_args("partial", root / "tasks", [first, second])
            real_copy = w.shutil.copy2

            def fail_second(src, dst, *pos, **kwargs):
                if str(dst).endswith("01-b.bin"):
                    raise OSError("injected copy failure")
                return real_copy(src, dst, *pos, **kwargs)

            with patch.object(w.shutil, "copy2", side_effect=fail_second):
                with self.assertRaises(OSError):
                    w.init(args)
            self.assertFalse((args.root / args.name).exists())
            self.assertEqual(list(args.root.glob(".init-*")), [])
            quiet_init(args)
            with self.assertRaises(ValueError):
                w.init(args)
            self.assertEqual(list(args.root.glob(".init-*")), [])

    def test_round_trip_does_not_pass_until_evidence_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sample.txt"
            source.write_text("sample", encoding="utf-8")
            args = init_args("round", root / "tasks", [source])
            quiet_init(args)
            task = args.root / args.name
            self.assertEqual(w.delivery_errors(task), ["缺少flag.txt或WP.md"])
            with redirect_stdout(io.StringIO()):
                w.triage(SimpleNamespace(challenge=task))
            write_passing(task)
            self.assertEqual(w.delivery_errors(task), [])
            (task / "original/00-sample.txt").write_text("tampered", encoding="utf-8")
            self.assertIn("原件hash或归档路径不符", w.delivery_errors(task))


class TriageEdgeTest(unittest.TestCase):
    def test_classify_prefers_content_and_keeps_apk(self):
        cases = (
            (Path("a.php"), "ELF 64-bit LSB", "reverse/pwn：依输入约束及服务行为区分"),
            (Path("a.php"), "gzip compressed data", "misc/forensics：先检查容器与结构"),
            (Path("a.php"), "PHP script, ASCII text", "web/reverse：依执行位置判断"),
            (Path("a.html"), "PNG image data", "misc/forensics：先检查容器与结构"),
            (Path("a.apk"), "Zip archive data", "reverse"),
            (Path("a.ts"), "MPEG transport stream", "misc/forensics：先检查容器与结构"),
            (Path("a.ts"), "ASCII text", "web/reverse：依执行位置判断"),
            (Path("a.pcap"), "pcap-ng capture file", "forensics/misc"),
            (Path("mod.wasm"), "data", "reverse"),
            (Path("plain.bin"), "data", w.GENERIC),
            (Path("x"), "wasm binary", "reverse"),
        )
        for path, info, expected in cases:
            self.assertEqual(w.classify(path, info), expected, info)
        self.assertEqual(w.magic_hint(b"\x7fELF" + b"\x00" * 8), "ELF")
        self.assertEqual(w.magic_hint(b"\x89PNG\r\n\x1a\n" + b"\x00"), "image")
        self.assertEqual(w.magic_hint(b"not magic"), "")

    def test_option_like_name_is_passed_after_double_dash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "-odd.txt"
            source.write_text("odd", encoding="utf-8")
            args = init_args("odd", root / "tasks", [source])
            quiet_init(args)
            task = args.root / args.name
            with redirect_stdout(io.StringIO()):
                w.triage(SimpleNamespace(challenge=task))
            report = json.loads((task / "evidence/triage.json").read_text(encoding="utf-8"))
            self.assertEqual(report[0]["file_command"][2], "--")
            self.assertTrue(str(report[0]["file_command"][-1]).endswith("-odd.txt"))

    def test_only_invokes_file_without_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sample.txt"
            source.write_text("sample", encoding="utf-8")
            args = init_args("safe", root / "tasks", [source])
            quiet_init(args)
            with patch.object(w.subprocess, "run", wraps=w.subprocess.run) as invoked:
                with redirect_stdout(io.StringIO()):
                    w.triage(SimpleNamespace(challenge=args.root / args.name))
            self.assertTrue(invoked.called)
            for call in invoked.call_args_list:
                self.assertEqual(call.args[0][0], "file")
                self.assertFalse(call.kwargs.get("shell", False))

    def test_missing_file_command_uses_header_without_overriding_real_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = root / "elf.bin"
            text = root / "note.txt"
            elf.write_bytes(b"\x7fELF" + b"\x00" * 16)
            text.write_text("text", encoding="utf-8")
            args = init_args("headers", root / "tasks", [elf, text])
            quiet_init(args)
            task = args.root / args.name
            error = io.StringIO()
            with patch.object(w.shutil, "which", return_value=None):
                with redirect_stdout(io.StringIO()), redirect_stderr(error):
                    w.triage(SimpleNamespace(challenge=task))
            self.assertEqual(error.getvalue().count("WARNING"), 1)
            self.assertIn("未找到 file 命令", error.getvalue())
            report = json.loads((task / "evidence/triage.json").read_text(encoding="utf-8"))
            self.assertIsNone(report[0]["file_exit"])
            self.assertEqual(report[0]["file_output"], "")
            self.assertEqual(report[0]["file_command"][0], "file")
            self.assertEqual(report[0]["category_hint"], "reverse/pwn：依输入约束及服务行为区分")
            self.assertTrue(report[0]["header_hex"].startswith("7f454c46"))
            self.assertEqual(report[1]["category_hint"], w.GENERIC)

            def fake_file(*pos, **kwargs):
                return SimpleNamespace(stdout="data\n", returncode=0)

            with patch.object(w.shutil, "which", return_value="/usr/bin/file"):
                with patch.object(w.subprocess, "run", side_effect=fake_file):
                    with redirect_stdout(io.StringIO()):
                        w.triage(SimpleNamespace(challenge=task))
            report = json.loads((task / "evidence/triage.json").read_text(encoding="utf-8"))
            self.assertEqual(report[0]["file_output"], "data")
            self.assertEqual(report[0]["file_exit"], 0)
            self.assertEqual(report[0]["category_hint"], w.GENERIC)

    def test_file_timeout_does_not_write_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sample.txt"
            source.write_text("sample", encoding="utf-8")
            args = init_args("slow", root / "tasks", [source])
            quiet_init(args)
            task = args.root / args.name
            with patch.object(w.shutil, "which", return_value="/usr/bin/file"):
                with patch.object(
                    w.subprocess,
                    "run",
                    side_effect=subprocess.TimeoutExpired(cmd=["file"], timeout=10),
                ):
                    with self.assertRaises(ValueError) as caught:
                        w.triage(SimpleNamespace(challenge=task))
            self.assertIn("超时", str(caught.exception))
            self.assertFalse((task / "evidence/triage.json").exists())

    def test_manifest_path_and_symlink_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sample.txt"
            source.write_text("sample", encoding="utf-8")
            args = init_args("paths", root / "tasks", [source])
            quiet_init(args)
            task = args.root / args.name
            manifest_path = task / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            manifest["files"][0]["archived"] = "original/../../outside.txt"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                w.triage(SimpleNamespace(challenge=task))
            self.assertIn("归档路径不在original目录", str(caught.exception))

            archived = task / "original/00-sample.txt"
            archived.unlink()
            archived.symlink_to(outside)
            manifest["files"][0]["archived"] = "original/00-sample.txt"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                w.triage(SimpleNamespace(challenge=task))
            self.assertIn("归档路径不在original目录", str(caught.exception))

            archived.unlink()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                w.triage(SimpleNamespace(challenge=task))
            self.assertIn("归档文件不存在", str(caught.exception))

            manifest_path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                w.triage(SimpleNamespace(challenge=task))
            self.assertIn("无法解析", str(caught.exception))

    def test_symlinked_original_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sample.txt"
            source.write_text("sample", encoding="utf-8")
            args = init_args("linked", root / "tasks", [source])
            quiet_init(args)
            task = args.root / args.name
            real = task / "original-real"
            (task / "original").rename(real)
            (task / "original").symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError) as caught:
                w.triage(SimpleNamespace(challenge=task))
            self.assertIn("归档路径不在original目录", str(caught.exception))

    def test_empty_attachment_triage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = init_args("empty", root / "tasks")
            quiet_init(args)
            task = args.root / args.name
            with redirect_stdout(io.StringIO()):
                w.triage(SimpleNamespace(challenge=task))
            self.assertEqual(json.loads((task / "evidence/triage.json").read_text(encoding="utf-8")), [])


class CheckEdgeTest(unittest.TestCase):
    def test_success_edges_and_failure_reasons(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary)
            record = write_passing(task)
            self.assertEqual(w.delivery_errors(task), [])
            (task / "flag.txt").write_bytes(FLAG.encode() + b"\r\n")
            self.assertEqual(w.delivery_errors(task), [])
            record["input"] = ""
            save_record(task, record)
            self.assertEqual(w.delivery_errors(task), [])
            record["command"] = "unit-test-fixture"
            save_record(task, record)
            self.assertEqual(w.delivery_errors(task), [])
            output = task / "evidence/output.txt"
            record["output_file"] = str(output.resolve())
            save_record(task, record)
            self.assertEqual(w.delivery_errors(task), [])
            for kind in sorted(w.KINDS):
                record["kind"] = kind
                save_record(task, record)
                self.assertEqual(w.delivery_errors(task), [], kind)

            record = write_passing(task)
            record["accepted"] = 1
            save_record(task, record)
            self.assertIn("验证未记录为通过", w.delivery_errors(task))
            record = write_passing(task)
            record["exit_status"] = 1
            save_record(task, record)
            self.assertIn("验证未记录为通过", w.delivery_errors(task))
            record = write_passing(task)
            record["kind"] = "guess"
            save_record(task, record)
            self.assertIn("验证类型未区分", w.delivery_errors(task))
            record = write_passing(task)
            record["command"] = ""
            save_record(task, record)
            self.assertIn("验证缺少精确命令或输入", w.delivery_errors(task))
            record = write_passing(task)
            del record["input"]
            save_record(task, record)
            self.assertIn("验证缺少精确命令或输入", w.delivery_errors(task))

            output.write_text("no flag here\n", encoding="utf-8")
            record = write_passing(task)
            output.write_text("no flag here\n", encoding="utf-8")
            record["output_sha256"] = w.sha256(output)
            save_record(task, record)
            self.assertIn("flag未出现在所引用的验证输出中", w.delivery_errors(task))

            write_passing(task)
            wp = (task / "WP.md").read_text(encoding="utf-8")
            (task / "WP.md").write_text(wp.replace(BODY, "太短", 1), encoding="utf-8")
            self.assertIn("初步观察与分析路线正文过少，检查是否只贴脚本", w.delivery_errors(task))
            write_passing(task)
            wp = (task / "WP.md").read_text(encoding="utf-8")
            (task / "WP.md").write_text(wp.replace(BODY, BODY + "\n```\n{{待填}}\n```\n", 1), encoding="utf-8")
            self.assertIn("WP残留模板占位符", w.delivery_errors(task))
            write_passing(task)
            wp = (task / "WP.md").read_text(encoding="utf-8")
            (task / "WP.md").write_text(wp.replace(BODY, BODY + "\n```python\nprint(1)\n", 1), encoding="utf-8")
            self.assertIn("代码块未闭合", w.delivery_errors(task))

            outside = task.parent / "outside.txt"
            outside.write_text(FLAG + "\n", encoding="utf-8")
            write_passing(task)
            record = load_record(task)
            record["output_file"] = str(outside)
            record["output_sha256"] = w.sha256(outside)
            save_record(task, record)
            self.assertTrue(any("越出" in item for item in w.delivery_errors(task)))

    def test_flag_heading_without_body_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary)
            write_passing(task)
            wp = (
                f"# 单元测试\n## 1. 初步观察与分析路线\n{BODY}\n{FLAG}\n"
                f"## 2. 逐步分析与解题\n{BODY}\n"
                "## 3. 完整 flag"
            )
            (task / "WP.md").write_text(wp, encoding="utf-8")
            self.assertEqual(
                w.delivery_errors(task),
                ["完整 flag末节只放完整flag，其后立即结束"],
            )

    def test_heading_inside_fence_does_not_truncate_section(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary)
            write_passing(task)
            long = "这是足够长的正文用于确认代码块里的标题不会截断本节的长度统计。" * 3
            fence = "```text\n## 8. 假标题\ncode\n```\n"
            wp = (
                f"# 单元测试\n## 1. 初步观察与分析路线\n短\n{fence}{long}\n"
                f"## 2. 逐步分析与解题\n{long}\n"
                f"## 3. 完整 flag\n\n```text\n{FLAG}\n```\n"
            )
            (task / "WP.md").write_text(wp, encoding="utf-8")
            self.assertEqual(w.delivery_errors(task), [])

    def test_special_files_and_bad_records_do_not_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary)
            write_passing(task)
            link = task / "evidence" / "link.txt"
            outside = task.parent / "linked.txt"
            outside.write_text(FLAG + "\n", encoding="utf-8")
            link.symlink_to(outside)
            record = load_record(task)
            record["output_file"] = "evidence/link.txt"
            record["output_sha256"] = w.sha256(outside)
            save_record(task, record)
            self.assertTrue(any("证据路径越出题目目录" in item for item in w.delivery_errors(task)))

            pipe = task / "evidence" / "pipe"
            os.mkfifo(pipe)
            record["output_file"] = "evidence/pipe"
            record["output_sha256"] = "0" * 64
            save_record(task, record)
            self.assertTrue(any("证据路径越出题目目录" in item for item in w.delivery_errors(task)))

            (task / "evidence/validation.json").write_text("[]", encoding="utf-8")
            self.assertTrue(any("必须是对象" in item for item in w.delivery_errors(task)))
            (task / "evidence/validation.json").write_text("{", encoding="utf-8")
            self.assertTrue(any(item.startswith("验证记录错误:") for item in w.delivery_errors(task)))
            (task / "manifest.json").write_text("{", encoding="utf-8")
            write_passing(task)
            (task / "manifest.json").write_text("{", encoding="utf-8")
            errors = w.delivery_errors(task)
            self.assertTrue(any(item.startswith("manifest.json") for item in errors))
            (task / "manifest.json").write_text(
                json.dumps({"files": [{"archived": "original/missing.bin", "sha256": "ab"}]}),
                encoding="utf-8",
            )
            self.assertIn("原件hash或归档路径不符", w.delivery_errors(task))

            not_dir = task.parent / "not-a-directory"
            not_dir.write_text("x", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                w.delivery_errors(not_dir)
            self.assertIn("必须是目录", str(caught.exception))


class ProfileAndTemplateTest(unittest.TestCase):
    def test_template_copy_matches_canonical(self):
        canonical = REPO / "prep/templates/WP.template.md"
        bundled = REPO / "skills/whuctf-solver/assets/WP.template.md"
        self.assertEqual(canonical.read_bytes(), bundled.read_bytes())

    def test_profile_validation(self):
        loaded = w.load_profile(w.PROFILE_PATH)
        self.assertEqual(loaded["flag_prefixes"], ["WHUCTF", "whuctf", "flag"])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps({"flag_prefixes": ["flag"], "priority": ["reverse"]}), encoding="utf-8")
            self.assertEqual(w.load_profile(path)["priority"], ["reverse"])
            for payload in (
                {"flag_prefixes": []},
                {"flag_prefixes": [""]},
                {"flag_prefixes": ["bad{"]},
                {"flag_prefixes": ["has space"]},
                [],
            ):
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    w.load_profile(path)
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                w.load_profile(path)
        with patch.object(w, "PROFILE", {"flag_prefixes": ["demo"]}):
            self.assertTrue(w.valid_flag("demo{abc}"))
            self.assertFalse(w.valid_flag("flag{abc}"))
        self.assertFalse(w.valid_flag(None))
        self.assertFalse(w.valid_flag("WHUCTF{x}\r\n"))
        self.assertEqual(w.local_tz().utcoffset(datetime.now(timezone.utc)), timedelta(hours=8))
        with patch.object(w, "ZoneInfo", side_effect=w.ZoneInfoNotFoundError("missing")):
            self.assertEqual(w.local_tz().utcoffset(None), timedelta(hours=8))


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_help_and_usage_errors(self):
        help_proc = self.run_cli("-h")
        self.assertEqual(help_proc.returncode, 0)
        self.assertIn("init", help_proc.stdout)
        self.assertIn("退出码", help_proc.stdout)
        self.assertEqual(self.run_cli().returncode, 2)
        with tempfile.TemporaryDirectory() as temporary:
            proc = self.run_cli("init", "--name", "../x", "--root", temporary)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("ERROR:", proc.stderr)
            self.assertNotIn("INITIALIZED=", proc.stdout)
            with redirect_stderr(io.StringIO()):
                code = w.main(["init", "--name", "..", "--root", temporary])
            self.assertEqual(code, 2)

    def test_init_triage_and_check_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sample.txt"
            source.write_text("sample", encoding="utf-8")
            description = root / "prompt.md"
            description.write_text("题面\n", encoding="utf-8")
            task_root = root / "tasks"
            init_proc = self.run_cli(
                "init",
                "--name",
                "demo",
                "--root",
                str(task_root),
                "--attachment",
                str(source),
                "--description-file",
                str(description),
                "--url",
                "https://example.invalid/task",
            )
            self.assertEqual(init_proc.returncode, 0, init_proc.stderr)
            self.assertIn("INITIALIZED=", init_proc.stdout)
            task = task_root / "demo"
            triage_proc = self.run_cli("triage", str(task))
            self.assertEqual(triage_proc.returncode, 0, triage_proc.stderr)
            self.assertIn("sha256", triage_proc.stdout)
            self.assertNotIn("WARNING", triage_proc.stderr)
            check_proc = self.run_cli("check", str(task))
            self.assertEqual(check_proc.returncode, 1)
            self.assertIn("FAIL:", check_proc.stdout)
            missing = self.run_cli("check", str(root / "missing"))
            self.assertEqual(missing.returncode, 2)
            self.assertIn("题目目录不存在", missing.stderr)
            not_dir = root / "file"
            not_dir.write_text("x", encoding="utf-8")
            rejected = self.run_cli("check", str(not_dir))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("必须是目录", rejected.stderr)
            write_passing(task)
            passed = self.run_cli("check", str(task))
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            self.assertIn("PASS:", passed.stdout)


if __name__ == "__main__":
    unittest.main()
