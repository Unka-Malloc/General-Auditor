# General-Auditor

General-Auditor 为 **SymPolicy、Meshrix-Platform、LicoLand 的全部公开仓库**提供统一审计规则、各仓库专属规则和一份滚动 HTML 报告。

**[查看最近 30 天的审计报告](https://unka-malloc.github.io/General-Auditor/)** · [报告源文件](reports/index.html) · [运行记录](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/audit.yml) · [文档入口](docs/README.md)

规则以本机 Agent 的上下文判断为主。CI 只收集确定性的审计信号，不调用付费 Agent，不验证凭据，不执行被审计仓库的代码。关键词命中产生 `warning / unreviewed`，不会导致 CI 失败；网络、配置或扫描器故障会明确失败。

## 已实现

- 必须遵守的[通用政策](docs/common-policy.md)，以及每个仓库独立的 [profile](profiles/)；没有 profile 时使用统一初始化模板。
- 不依赖 `src/`、`docs/`、`AGENTS.md` 或某个固定分支。仓库额外要求的路径必须在其 profile 中单独声明。
- 中央 CI 每 15 分钟发现公开分支与开放 PR 的变化，只扫描变化的仓库和对应提交区间。手动入口可指定单个仓库，或显式选择 `all`。
- 首次或手动扫描读取当前分支快照；后续扫描读取区间内每次提交的变更，包含后来删除的内容。相同仓库、相同提交、相同范围合并扫描。
- `reports/index.html` 是唯一固定 HTML 报告。`reports/data.json` 保存最近 30 天的脱敏结果；每次自动运行都会清理过期条目，包括没有代码变化时。
- 已为当前发现的 32 个公开仓库初始化专属 Agent 检查要求。以后发现的新公开仓库自动初始化通用 profile。

GitHub 定时工作流可能延迟或被平台停用，轮询不是逐事件的实时交付保证。报告中的告警不是泄露结论；无告警也不等于安全。[扫描范围与限制](docs/architecture.md)说明了完整边界。

## 本机使用

需要 Python 3.11+ 和 Git。运行时只有 Python 标准库依赖。

```sh
git clone https://github.com/Unka-Malloc/General-Auditor.git
cd General-Auditor
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --output out/audit.json
```

`scan` 读取已提交的 Git 内容，不读取未提交的工作区修改。提交到本地后、首次 push 前，让本机 Agent 按通用政策和仓库 profile 审阅结果。指定 `--base <previous-commit>` 可审查完整提交区间。扫描私有仓库时输出默认标为 `private`，不会进入中央公开报告。

初始化只新增缺失文件，不覆盖现有文件，不移动源码或文档。需要仓库内即时 CI 时追加 `--with-workflow`；这会添加 `.github/workflows/general-auditor.yml`。三个组织的公开仓库已经通过中央 profile 接入，**无需向这些仓库提交初始化文件就能执行通用规则**。[初始化与 CI 模板](docs/initialization.md)

## 中央 CI

```sh
# 维护者操作：只扫描指定仓库
gh workflow run audit.yml -R Unka-Malloc/General-Auditor -f repository=LicoLand/LicoArc

# 维护者操作：显式批量扫描所有公开仓库
gh workflow run audit.yml -R Unka-Malloc/General-Auditor -f repository=all
```

中央工作流仅使用其自带的 `GITHUB_TOKEN`，不需要贡献者的 API 密钥，不接受来自公开 PR 的任意付费 Agent 调用。公开报告只发布脱敏类别、Git 文件位置、规则、判断状态、依据、影响和处理建议。

## 验证

```sh
python3 tools/verify.py
```

该入口检查源码语法、规则和 profile 契约，并执行使用临时 Git 仓库的确定性集成测试。真实 Agent 审阅由贡献者在本机完成，不由此验证入口启动。

规则设计参考 [Lico-Auditor](https://github.com/LicoLand/Lico-Auditor) 和 [styio-audit](https://github.com/SymPolicy/styio-audit)，保留二者作为独立项目。[整合范围](docs/policy-sources.md)
