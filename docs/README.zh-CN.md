# General-Auditor

[English](../README.md) · [仓库清单](repositories.md) · [检查覆盖](audit-coverage.md)

General-Auditor 为 SymPolicy、Meshrix-Platform 和 LicoLand 提供通用规则与仓库专属检查。CI 只返回安全的状态及数量摘要；详细审计报告仅在本机生成，显示实际命中的原文、上下文、位置和规则说明。

| 组织 | 继续维护的公开仓库 | 已私有归档的旧 Auditor |
| --- | ---: | ---: |
| SymPolicy | 17 | 1 |
| Meshrix-Platform | 4 | 0 |
| LicoLand | 9 | 1 |

完整分组见[仓库清单](repositories.md)。各仓库提交只触发自身通用规则和专属检查，保留独立的功能检查及原有分支合并流程。

## 本机报告

在可信 General-Auditor 源码目录运行：

```sh
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope worktree
```

打开目标仓库的 `.general-auditor/local/index.html`。所有生成数据固定保存在目标 Git 根目录下的 `.general-auditor/local/`，并被 Git 忽略。已有被跟踪的文件需要保留本地数据后从索引取消跟踪；单独添加忽略规则不能撤回历史上传。

原始命中文本仅允许进入这些私有本地文件，不能输出到终端、聊天、PR、CI 日志或云端产物。报告保留组织/仓库侧栏、历史与范围选择、实际命中规则及上下文。旧脱敏归档无法还原未保存的原文，必须对实际源版本重新扫描。

`staged` 检查暂存区，`worktree` 检查当前工作文件，`snapshot` 检查指定提交快照，`range` 检查指定基线后的提交版本，`history` 检查选定提交可达的全部历史。未读取的内容和不完整检查必须明确保留。

自动匹配是待判断的候选项，不等于真实泄露。由本机 Agent 根据源内容判断误报、确认问题或具体不确定项；零命中也不代表已经证明安全。参见[本机审查指南](../general_auditor/templates/LOCAL-REVIEW.md)。

## CI 与维护

公开报告服务、Pages 发布、云端报告上传和集中轮询已退出当前实现。CI 使用只返回摘要的 `check`，不调用付费 Agent、不生成原文报告。本地报告及审查命令拒绝在 CI 环境运行。

所有继续维护的公开仓库均须接入 `Unka-Malloc/General-Auditor@only`。已有迁移 PR 的创建不代表默认分支已经切换。官网、独立文档、基准测试和组织展示仓库保持维护者管制。

Auditor 唯一永久分支为 `only`；指定维护者通过临时 `work/*` 分支 PR 合并，禁止直接推送、外部 PR 和版本命名工作流。默认 README 使用英文。定向修复及源码审阅完成后运行 `python3 tools/verify.py`，以合成数据验证工程行为；真实 Agent 审查另行执行。
