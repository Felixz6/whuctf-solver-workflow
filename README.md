# WHUCTF Solver Workflow

一套面向 WHUCTF/CTF 的题目归档 CLI、中文解题技能和 WP 模板。项目由个人工作流整理而成，与赛事主办方无隶属或背书关系；具体题目仍按题面和比赛当次规则处理。

工具只处理题面，以及用户明确指定的本地附件路径：不执行附件、不连接网络、不自动提交 flag。

## 内容

- `prep/scripts/whuctf.py`：归档输入、静态分诊、检查 WP 与验证证据的结构。
- `prep/whuctf-profile.json`：flag 前缀和其他工作流备忘。CLI 只强制使用 `flag_prefixes`。
- `prep/templates/WP.template.md`：`init` 写入 `WP.md` 的模板，是模板的唯一来源。
- `prep/tests/`：标准库单元测试。
- `skills/whuctf-solver/`：可单独拷贝的解题技能。其中 `assets/WP.template.md` 必须与上面的模板保持一致。

## 要求

- Python 3.9 或更高版本。CLI 和测试只使用标准库。
- 文本按 UTF-8 读写。写出的题目文件使用 LF。`flag.txt` 读入时接受 LF 或 CRLF，并只去掉至多一个结尾换行。
- `triage` 在 `PATH` 里能找到 `file` 时用它识别类型。有附件但没有该命令时，仍校验 hash，向标准错误打印一条警告，并只根据扩展名和文件头给出分类提示。

可以从任意工作目录运行。`prep/` 的位置按脚本文件解析，不依赖当前目录。

## 使用

```bash
python3 -m unittest discover -s prep/tests -v
python3 prep/scripts/whuctf.py init --name sample --description-file prompt.md --attachment challenge.bin --url https://example.invalid/task
python3 prep/scripts/whuctf.py triage challenges/sample
python3 prep/scripts/whuctf.py check challenges/sample
```

`init` 把附件复制到 `original/`，再复制一份到 `work/`，并写 `manifest.json`、`description.md`、`notes.md` 和 `WP.md`。复制后核对 SHA-256。输入不合法、原件在复制过程中被改动，或题目目录已存在时，命令失败，不会留下半个题目目录。真旗确认前不创建 `flag.txt`。符号链接附件会按目标普通文件的内容归档，管道和目录会被拒绝。

`triage` 重新计算 `original/` 的 SHA-256，与 manifest 不一致即失败。它不跟随 `original/` 里的符号链接。分类提示只供参考，不参与 `check`。

`check` 检查结构，不证明 flag 或 WP 推理正确，也不会访问题目服务。

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | `check` 未通过。原因以 `FAIL:` 打在标准输出 |
| 2 | 参数、路径或运行错误。原因以 `ERROR:` 打在标准错误 |

损坏的 `manifest.json`、缺失的原件和无法解析的验证记录都算结构问题，走退出码 1。题目目录不存在或路径不是目录，走退出码 2。

### 题目名

`--name` 只接受一个目录名。空串、`.`、`..`、路径分隔符、控制字符、`<>:"|?*`、首尾空白和结尾点号都会被拒绝。中文、中间的空格和中间的点号可以使用。名称按 UTF-8 计，最长 255 字节。这样生成的目录可以在 Windows 上保存。

### 安装技能

将 `skills/whuctf-solver/` 复制到 agent 的技能目录，例如 Codex 的 `.agents/skills/whuctf-solver/`，或 DeepSeek Harness 的 `.dsh/skills/whuctf-solver/`。然后重载或重新打开 agent。

技能目录里的 WP 模板是副本，便于单独安装。修改措辞时以 `prep/templates/WP.template.md` 为准，并同步副本。测试会检查两份文件的字节一致。

## 结构检查

`flag.txt`、`WP.md` 和 `evidence/validation.json` 都存在时，`check` 核对：

- flag 匹配 `flag_prefixes`，除已去掉的结尾换行外没有控制字符
- WP 从「初步观察与分析路线」连续编号到「完整 flag」
- 末节只有 flag 本身，或只包在信息字符串为 `text` 或为空的代码块里
- 没有模板占位符、未闭合的代码块，且前两节不只是脚本
- 验证记录的类型、通过标记、命令、输入、输出路径和 SHA-256，以及输出中是否出现 flag
- 若存在 `manifest.json`，原件仍是 `original/` 下的普通文件且 hash 未变

写法上的其他要求见 `skills/whuctf-solver/references/writeup-contract.md`。那里把检查器强制执行的条件和只要求作者遵守的写法分开写了。

## 本地题目数据

默认题目目录是 `challenges/`。其中会有附件、日志、候选和最终 flag，已被 `.gitignore` 排除。不要把真实题目数据、平台凭据或 flag 提交到公共仓库。

`prep/whuctf-profile.json` 不含服务凭据。按当次赛事修改 `flag_prefixes`；本文件里的示例和历史规则都不能代替赛事说明。`priority`、`writeup_mode`、`final_files` 和 `require_validation_evidence` 只是工作流备忘，CLI 不读取。`check` 始终要求验证记录，不能靠把 `require_validation_evidence` 改成 false 来跳过。

## 许可

MIT，见 [LICENSE](LICENSE)。
