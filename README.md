# WHUCTF Solver Workflow

面向 WHUCTF/CTF 的个人题目归档 CLI、中文解题技能和 WP 模板。与赛事主办方无隶属或背书关系；具体题目仍按题面和当次比赛规则处理。

**边界：** 只处理题面，以及你明确指定的本地附件路径。不执行附件、不连接网络、不自动提交 flag。真旗由你手动验证；`check` 只做本地结构与证据一致性检查。

## 仓库里有什么

| 路径 | 作用 |
|---|---|
| `prep/scripts/whuctf.py` | `init` / `triage` / `check` |
| `prep/whuctf-profile.json` | flag 前缀等备忘；CLI 只使用 `flag_prefixes` |
| `prep/templates/WP.template.md` | `init` 写入 `WP.md` 的模板（权威来源） |
| `prep/tests/` | 标准库单元测试 |
| `skills/whuctf-solver/` | 可单独安装的解题技能；内含 WP 模板副本 |
| `challenges/` | 默认题目目录（已 gitignore，勿提交真实题数据） |

## 环境

- Python 3.9+；CLI 与测试仅用标准库
- 文本按 UTF-8；写出的题目文件使用 LF
- `triage` 可选系统 `file`（常见于 macOS / Linux）。没有也能跑：仍校验 hash，并按扩展名与文件头给分类提示

脚本路径按文件位置解析，可在任意工作目录调用。

## 快速开始

在仓库根目录：

```bash
python3 -m unittest discover -s prep/tests -v

python3 prep/scripts/whuctf.py init \
  --name sample \
  --description-file prompt.md \
  --attachment challenge.bin \
  --url https://example.invalid/task

python3 prep/scripts/whuctf.py triage challenges/sample
python3 prep/scripts/whuctf.py check challenges/sample
```

更多参数见 `python3 prep/scripts/whuctf.py -h` 与各子命令 `-h`。

## 命令说明

### `init` — 建题归档

生成 `challenges/<name>/`（可用 `--root` 改根目录），大致结构：

```text
challenges/sample/
  description.md      # 题面
  manifest.json       # 名称、时间、URL、原件 sha256
  notes.md            # 过程记录
  WP.md               # 由模板生成
  original/           # 原件（勿改）
  work/               # 可改的工作副本
  evidence/           # 分诊与验证证据
```

要点：

- 附件先拷到 `original/`，再拷到 `work/`；核对 SHA-256；去掉归档副本的可执行位（源文件不动；要跑就在 `work/` 里自己 `chmod`）
- 真旗确认前不创建 `flag.txt`
- 输入非法、复制中途失败或目录已存在时失败，不留半成品；下次 `init` 还会清掉同根下残留的 `.init-*`
- 符号链接按目标普通文件归档；目录 / 管道拒绝
- `--name`：单一目录名；拒绝路径分隔符、控制字符、`<>:"|?*`、首尾空白、结尾点号、Windows 保留名（如 `CON`、`COM1`）；中文与中间空格可用；最长 255 字节（UTF-8）

### `triage` — 静态分诊

- 重算 `original/` 的 SHA-256，与 manifest 不一致则失败
- 不跟随 `original/` 内的符号链接，不执行附件
- 有 `file` 则记录其输出；输出为空或仅为 `data` / `empty` 时，用文件头补分类提示
- 写出 `evidence/triage.json`；`category_hint` 仅供参考，不参与 `check`

### `check` — 交付结构检查

核对 `flag.txt`、`WP.md`、`evidence/validation.json`（及可选的 `manifest.json`）是否自洽。

它**不**证明 flag 正确、**不**评判 WP 推理、**不**访问题目服务或平台。通过后仍须你自己复现或人工确认。

详细强制项与写作约定见 [`skills/whuctf-solver/references/writeup-contract.md`](skills/whuctf-solver/references/writeup-contract.md)。摘要：

- flag 匹配 `flag_prefixes`；`flag.txt` 允许 LF/CRLF，读入后只去掉至多一个结尾换行
- WP 从「初步观察与分析路线」连续编号到「完整 flag」；末节只放 flag
- 正文（不含代码块）无 `{{...}}` / `TODO` / `TBD`；代码块须闭合；前两节不能只有脚本
- 验证记录含合法 `kind`、`accepted: true`、命令与输入、题目录内输出文件及其 sha256，且输出中出现 flag

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | `check` 未通过（`FAIL:` → 标准输出） |
| 2 | 参数 / 路径 / 运行错误（`ERROR:` → 标准错误） |

结构问题（坏 manifest、缺原件、坏验证记录）用 **1**。题目目录不存在或不是目录用 **2**。

## 配置与本地数据

编辑 `prep/whuctf-profile.json` 的 `flag_prefixes` 以匹配当次赛事；示例不代替赛事说明。文件不含服务凭据。

`priority`、`writeup_mode`、`final_files`、`require_validation_evidence` 只是备忘，**CLI 不读**。`check` 始终要求验证记录，不能靠改配置关掉。

`challenges/` 会含附件、日志、候选与最终 flag，默认被忽略。不要把真实题目数据、平台凭据或 flag 推到公共仓库。

## 安装解题技能

把 `skills/whuctf-solver/` 拷到 agent 技能目录，例如：

- Codex：`.agents/skills/whuctf-solver/`
- DeepSeek Harness：`.dsh/skills/whuctf-solver/`

然后重载或重新打开 agent。

技能内 `assets/WP.template.md` 是副本，方便单独安装；改措辞以 `prep/templates/WP.template.md` 为准并同步副本。测试会检查两份字节一致。

## 许可

MIT，见 [LICENSE](LICENSE)。
