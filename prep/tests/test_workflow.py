import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

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


if __name__ == "__main__":
    unittest.main()
