# AI Software Delivery Factory

你描述产品需求，工厂负责规划、开发、测试、独立审核和自动返工，最后交回可验收的候选版本。你不需要给每个 Agent 写下一条 Prompt。

Harness 管需求、权限、预算、证据和交付门禁；**官方 Codex 管编程、调试和审核智能**。最终 merge / release 始终由人明确批准，工厂没有自动合并或发布执行器。

## 先体验：不需要 API key，不产生 Provider 费用

需要 Python 3.11+、Git。Linux 上真实执行还需要 Codex CLI 和 bubblewrap。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
source .venv/bin/activate
harness factory-demo
```

不安装也可以运行：

```bash
PYTHONPATH=src python3 -m harness.cli factory-demo
```

演示会创建临时小项目，实现 `average(values)`，运行真实 Python 测试和本地 CI 检查。fixture reviewer 发现遗漏的整数除法 bug，工厂自动修复并补回归测试，然后重新测试、重新审核。最终输出包含：

```text
DELIVERY_STATUS=READY_FOR_USER_ACCEPTANCE
TEST_RESULT=PASS
CI_RESULT=PASS
MERGE_PERFORMED=false
SIMULATION=true
```

完整 JSON 给出源码目录、目标 commit、证据文件和 `acceptance-report.json` 的位置。fixture 审核明确标记为模拟，不是正式 OpenAI / DeepSeek receipt。

## 一次性配置真实项目

项目负责人完成一次配置，日常使用者之后只提交需求：

```bash
mkdir -p ~/.config/codex-factory
cp config/factory.example.json ~/.config/codex-factory/config.json
chmod 600 ~/.config/codex-factory/config.json
```

在配置中设置项目已有的测试、CI 命令，以及 DeepSeek token 文件的绝对路径。token 文件必须属于当前用户，权限 `0600`。示例面向 FootballPrediction；其他项目使用自己的验证命令。工厂不会降低、删掉或自动改写这些门禁。

OpenAI 的 `model` / `codex_profile` 可以省略，由官方 Codex 配置选择，也可以为 developer / reviewer 各自配置。需要选择单独认证目录时，在对应 profile 加入 `"codex_home": "/absolute/private/codex/home"`；该目录必须属于当前用户且不可被其他用户写入。工厂不会修改你的认证文件或全局模型配置。

```bash
harness factory-doctor
```

预算单位是 **Agent 执行次数**：示例最多 12 次、最多 3 轮开发/返工，每次有超时。一次执行指一个官方 Codex turn 或一个 DeepSeek 请求，不等于底层模型请求次数，也不是美元金额上限。Codex turn 内的工具/模型循环有时间上限；未登记的 native subagent 扇出默认关闭。技术负责人、实施任务和审核使用独立官方线程。

真实 usage 仅按 Provider 遥测保存；缺失 usage、费用金额保持 `UNKNOWN`，失败执行不退还 reservation。需要严格金额上限时，同时配置 Provider 账户支出限额。本项目不会推测 Codex 订阅价格，也不继承或扩大 PR2 / PR4 的历史预算。

## 日常使用：提交需求，然后等交付

```bash
harness submit \
  --repository /absolute/path/to/FootballPrediction \
  --request '增加功能 X。满足 A/B/C，不改变现有生产行为。' \
  --mission-id football-feature-x \
  --acceptance '现有回归测试继续通过' \
  --constraint '禁止生产流量、quota 消耗和 Stage D'
```

可用 `--scope 'src/**' --scope 'tests/**'` 限定修改范围。项目已有已提交的 mission contract 时，传 `--mission-scope-file docs/agentic/missions/task.json`；工厂固定原始 Git blob，并只读交给项目验证器。

工厂在**独立 clone**里工作，原仓库、原分支、历史 ledger 和 evidence 不受任务执行影响。多个实施任务由独立 Codex 线程顺序执行；测试、CI 和 reviewer findings 自动触发返工。

关闭终端后：

```bash
harness factory-status football-feature-x
harness factory-resume football-feature-x
```

恢复复用已完成、哈希验证通过的证据。已登记请求的结果未知时停止为 `UNKNOWN`，不会偷偷重复付费请求。状态查询也验证 HEAD、scope 和 evidence；旧 READY 不会掩盖后来改动的源码或缺失的证据。

交付 JSON 包括 `IMPLEMENTED`、`TEST_RESULT`、`CI_RESULT`、`REVIEW_RESULT`、`BLOCKERS_REMAINING`、`KNOWN_RISKS`、`BUDGET_USED`、`TARGET_HEAD` 和 `DELIVERY_EVIDENCE`。`CI_RESULT` 指配置中的本地 CI 命令，**不代表已经通过 GitHub hosted checks**。

验收后，可以记录对 exact HEAD 的明确批准：

```bash
harness factory-approve football-feature-x \
  --action merge --head <TARGET_HEAD> --reason '已验收，批准这个版本'
```

该命令只记录批准，不执行 merge。发布和最终合并仍由现有人工流程完成。模拟任务不能获得真实 merge / release 批准。

## 当前边界

普通测试失败、CI 命令失败、review findings 自动返工。重大产品歧义返回 `WAITING_PRODUCT_DECISION`；预算、返工次数、容量或安全边界不足返回明确 blocker。格式/source reference 校验失败时，只有已经证明完成的审核允许一次新的、有预算登记的恢复尝试；未知 dispatch 不会重发。

OpenAI 审核复用官方 review rubric 和 App Server structured turn。DeepSeek 使用独立 HTTPS API 和相同官方 rubric，拿不到 OpenAI 结论。两个 lane 审核整个 `base..head` diff。容量不足停止，不切 chunk、不截断、不假装全量审核成功。

目前支持本地 Linux、配置好的项目门禁和双 Provider 审核。DeepSeek 发送有容量上限的完整 tracked 文本源码上下文；大型仓库、二进制变更、变更的 submodule 明确停止。暂不自动 push、创建 PR、运行 hosted CI 或部署。live gates 中源码和 Git metadata 只读；构建产物应使用项目已有临时目录配置。认证、模型访问权和项目依赖需要在运行环境中就绪。

迁移验证使用本地/fixture、真实 Codex 零 inference 协议/权限检查、真实 bubblewrap 执行和全量治理测试。**尚未声明真实双 Provider 审核达到生产级。**

## 历史兼容

Reviewer V2 的 chunk/group/synthesis、固定 group 合约和旧 qualification 执行路径退出新任务流程。旧代码保留在显式 deprecated 路径，供历史兼容与治理回归验证；旧 receipts、ledger、UNKNOWN 不迁移、不改写、不退款。

旧 v1 `run` / `resume` 必须显式加 `--legacy`，live legacy 也禁止 `merge_policy=auto`。新任务使用 `submit`，或 version 2 mission 的 `factory-run`，无需 Reviewer V2 builder certificate。

[架构与迁移理由](docs/FACTORY_ARCHITECTURE.md) · [验证与验收证据](docs/FACTORY_VALIDATION.md)

```bash
make verify
```
