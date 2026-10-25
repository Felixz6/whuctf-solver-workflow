# WHUCTF Solver Workflow

一套面向 WHUCTF/CTF 的题目归档 CLI、中文解题技能和 WP 模板。项目由个人工作流整理而成，与赛事主办方无隶属或背书关系；具体题目仍按题面和比赛当次规则处理。

## 内容

- `prep/scripts/whuctf.py`：输入归档、静态分诊、WP 与验证证据结构检查。
- `prep/whuctf-profile.json`：可编辑的 flag 前缀、备战顺序和交付约定示例。
- `prep/tests/`：CLI 结构和验证门槛测试。
- `prep/templates/WP.template.md`：CLI 创建题目时使用的 WP 模板。
- `skills/whuctf-solver/`：可安装的解题技能及分类/WP参考。

## 要求

- Python 3.9 或更高版本；CLI 与测试使用 Python 标准库。
- `triage` 需要系统 `file` 命令（macOS、常见 Linux 发行版均提供）。

## 使用

在仓库根目录运行：

```bash
python3 -m unittest discover -s prep/tests -v
python3 prep/scripts/whuctf.py init --name sample --description-file prompt.md --attachment challenge.bin --url https://example.invalid/task
python3 prep/scripts/whuctf.py triage challenges/sample
python3 prep/scripts/whuctf.py check challenges/sample
```

输入参数按实际提供内容选择。`init` 将原件保存到 `original/`，并复制到 `work/`；不执行附件、不自动提交 flag。`triage` 校验归档 hash 并记录 `file` 输出。`check` 检查 `flag.txt`、WP 章节和验证证据的结构，不证明 flag 正确。

### 安装技能

将 `skills/whuctf-solver/` 复制到使用的 agent 技能目录，例如 Codex 的 `.agents/skills/whuctf-solver/`，或 DeepSeek Harness 的 `.dsh/skills/whuctf-solver/`。然后重载/重新打开 agent，使技能被发现。

## 本地题目数据

CLI 默认在 `challenges/` 新建题目目录，其中会含题目附件、日志、候选和最终 flag。此目录内容默认被 `.gitignore` 排除；不要把真实题目数据、平台凭据或 flag 加入公共提交。工具只适用于题面和用户明确指定的本地附件/题目服务，不面向无关资产。

`prep/whuctf-profile.json` 是可改配置，不含服务凭据。根据目标赛事格式编辑 `flag_prefixes`；历史规则或本项目示例不代替当次赛事说明。

## 许可

MIT，见 [LICENSE](LICENSE)。
