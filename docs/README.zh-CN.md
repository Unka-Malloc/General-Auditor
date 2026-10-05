# General-Auditor

[English](../README.md) · [文档目录](README.md) · [审计覆盖与迁移对照](audit-coverage.md) · [按组织和类别分组的仓库清单](repositories.md)

General-Auditor 为 **SymPolicy、Meshrix-Platform、LicoLand 的全部公开仓库**提供统一审计规则、各仓库专属规则和一份滚动 HTML 报告。

**[查看最近 30 天的审计报告](https://unka-malloc.github.io/General-Auditor/)** · [报告产物](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/publish-report.yml) · [运行记录](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/audit.yml) · [文档入口](README.md)

规则以本机 Agent 的上下文判断为主。CI 只收集确定性的审计信号，不调用付费 Agent，不验证凭据，不执行被审计仓库的代码。关键词命中产生 `warning / unreviewed`，不会导致 CI 失败；明确声明的结构性仓库契约失败会产生 `policy_failure`；输入不完整、网络、配置或扫描器故障产生 `incomplete`，两者都不是隐私泄露结论。

## 已实现

- 必须遵守的[通用政策](common-policy.md)，以及每个仓库独立的 [profile](../profiles/)；没有 profile 时使用统一初始化模板。
- [审计覆盖台账](audit-coverage.md)逐类对照 Lico-Auditor、styio-audit 与 General-Auditor 的规则、结构性检查、测试和明确替代项。
- 不依赖 `src/`、`docs/`、`AGENTS.md` 或某个固定分支。仓库额外要求的路径必须在其 profile 中单独声明。
- 中央 CI 每 15 分钟并发发现公开分支与开放 PR 的变化，发现一个就独立派发该仓库的工作流；慢仓库不阻塞其它仓库。手动入口可指定单个仓库，或显式选择 `all`。
- 首次或手动扫描读取当前分支快照；后续扫描读取区间内每次提交的变更，包含后来删除的内容。相同仓库、相同提交、相同范围合并扫描。
- 每个仓库完成后立即保存独立的 Actions 产物；独立发布器合并结果，更新唯一的 Pages HTML 报告与完整检查点，保留最近 30 天记录。每日刷新负责无代码变化时的过期清理，报告不再提交到源码分支。
- 当前公开清单为 30 个上游仓库；Lico-Auditor 与 styio-audit 已设为私有并归档，其独立 profile 已移除，有效共用规则仍保留。全部公开上游必须采用 General-Auditor CI。目前面向维护分支的 38 个迁移草稿 PR 尚未合并，不能宣称上游默认工作流已经切换。以后发现的新公开仓库在运行工作区自动初始化通用 profile；维护者通过 PR 保存专属规则。

GitHub 定时工作流可能延迟或被平台停用，轮询不是逐事件的实时交付保证。报告中的告警不是泄露结论；无告警也不等于安全。[扫描范围与限制](architecture.md)说明了完整边界。

## Auditor 维护

`only` 是唯一长期分支。当前指定维护者为 `Unka-Malloc`；改动通过仓库内临时 `work/*` 分支的 PR 合入，必须通过检查并解决讨论。管理员和机器人也不能直接推送 `only`。合并后自动删除临时分支。详见[贡献规则](contributing.md)。

## 本机使用

需要 Python 3.11+ 和 Git。运行时只有 Python 标准库依赖。

```sh
git clone https://github.com/Unka-Malloc/General-Auditor.git
cd General-Auditor
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope worktree --output out/audit.json
python3 -m general_auditor review-request --scan out/audit.json --output out/review-request.json --template out/review-handoff.json
# 请本机 Agent 结合源码审阅，填写 handoff.receipt_template 并将该对象另存为 out/review-receipt.json
python3 -m general_auditor review-complete --scan out/audit.json --receipt out/review-receipt.json --output out/review-report.json --html out/review-report.html
```

`scan` 支持 `snapshot`、`range`、`history`、`staged` 和 `worktree`。`staged` 读取暂存区；`worktree` 读取当前受跟踪文件及未被忽略的未跟踪文件。若提交内容同时包含暂存与未暂存状态，分别运行两种范围。`history` 检查指定 head 可达的全部提交；`range` 需要 `--base <previous-commit>`。未指定范围时，提供 `--base` 会选择区间，否则使用快照。CI 只读取不可变的事件提交，不检查贡献者本机文件。

`review-request --template` 写入包含 `receipt_template` 的交接文件；完成该对象后，将对象本身另存为回执，不能把整个交接文件交给 `review-complete`。本机 Agent 完成上下文审阅后，`review-complete` 校验回执并生成仅保存在本机的 JSON/HTML 报告。回执及已审阅报告不会作为公开 CI 结果，也不会上传。关键字或格式命中仍是 `warning / unreviewed`，CI 不调用付费 Agent。回执校验范围和完整性，但不能证明作者身份，也不能证明所有隐私信息都已脱敏。

初始化只新增缺失文件，不覆盖现有文件，不移动源码或文档。需要仓库内即时 CI 时追加 `--with-workflow`；这会添加 `.github/workflows/general-auditor.yml`。中央 profile 可以在没有初始化文件时执行通用检查；三个组织的全部继续维护上游仍必须接入仓库内 General-Auditor CI，中央轮询不能替代此要求。[初始化与 CI 模板](initialization.md)

## 中央 CI

```sh
# 维护者操作：只扫描指定仓库
gh workflow run audit.yml -R Unka-Malloc/General-Auditor -f repository=LicoLand/LicoArc

# 维护者操作：显式批量扫描所有公开仓库
gh workflow run audit.yml -R Unka-Malloc/General-Auditor -f repository=all -f force=true
```

中央工作流仅使用其自带的 `GITHUB_TOKEN`，不需要贡献者的 API 密钥，不接受来自公开 PR 的任意付费 Agent 调用。公开报告只发布脱敏类别、Git 文件位置、规则、判断状态、依据、影响和处理建议。

## 验证

```sh
python3 tools/verify.py
```

该入口检查源码语法、规则和 profile 契约，并执行使用临时 Git 仓库的确定性集成测试。真实 Agent 审阅由贡献者在本机完成，不由此验证入口启动。

网站、独立文档、基准测试和组织展示仓库会审计 GitHub PR 创建权限与分支 Ruleset。权限偏离会生成警告；只读 API 隐藏的 bypass 身份标记为“未核实”，由管理员工具检查完整配置。详见[访问控制](access-policy.md)。

规则覆盖和上游来源归属见 [Lico-Auditor](https://github.com/LicoLand/Lico-Auditor)、[styio-audit](https://github.com/SymPolicy/styio-audit) 及[来源说明](policy-sources.md)。两个旧 Auditor 的私有归档已经核实；旧本地检出和专属技能入口已清理，独立资产及未发布工作保存在私有备份中。归档与消费者 PR 合并是独立状态，公开来源链接可能需要访问权限。消费者现有分支可能仍引用旧 Auditor，直到迁移 PR 和必要的分支提升完成；私有化后，旧的匿名拉取可能失败。

第一方审计入口使用 `only`，不使用版本命名的工作流或 Auditor 版本标签。
