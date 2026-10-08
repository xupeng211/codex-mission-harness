# AI Software Delivery Factory

你说需求，Harness 自己规划、用官方 Codex 开发、运行测试和 CI、安排 OpenAI 与 DeepSeek 独立审核、处理 finding、自动返工，最后交回可信的候选版本。最终合并和发布需要你单独批准。

支持 Linux、Python 3.11–3.14，以及有真实测试命令的 Git 项目。首次配置后，日常只需三个入口：

```bash
harness submit "增加功能 X，保持现有功能正常"
harness status
harness delivery
```

真实双 Provider、自动返工、恢复及 GitHub CI 验收记录见 [交付验收](docs/PRODUCTION_ACCEPTANCE.md)。`factory-demo` 是免费模拟演示，不能用来证明真实 Provider 可用。

Codex 开发/规划可显式选择 [CLI proxy transport](docs/CLI_PROXY_TRANSPORT.md)，与官方 transport 分开配置。proxy OpenAI reviewer 尚未合格；DeepSeek reviewer 仍直接连接 Provider。developer route 可用不等于完整双 Provider Factory 已重新通过验收。

## 第一次安装与打开

安装 Python 3.11+、Git、Node.js 和 bubblewrap；GitHub Actions 项目还需要 GitHub CLI (`gh`)。Ubuntu 的系统组件可用 `sudo apt install python3-venv git bubblewrap` 安装。

```bash
npm install -g @openai/codex
git clone --branch feat/factory-production-acceptance https://github.com/xupeng211/codex-mission-harness.git
cd codex-mission-harness
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --index-url https://pypi.org/simple -e .
```

已有本仓库时可以从虚拟环境步骤开始；该 GitHub 仓库为私有仓库，需要有访问权限并先完成 `gh auth login`。

以后打开新的终端时，进入这个目录，执行 `source .venv/bin/activate`，就可以使用 `harness`。

## 一次性登录、配置项目

先通过官方 Codex 登录 OpenAI：

```bash
codex login
```

登录方式和安装说明以 [官方 Codex CLI 文档](https://developers.openai.com/codex/cli/) 为准。OpenAI reviewer 使用官方 OpenAI route，DeepSeek reviewer 使用官方直连。规划、开发和返工可显式使用 CLI proxy；[Hybrid Factory 配置](docs/HYBRID_FACTORY.md) 使用独立官方认证目录，不覆盖日常 Codex 配置。

从 DeepSeek 账户获得 API key，然后告诉 Harness 你的项目目录：

```bash
harness setup --repository /你的项目完整路径
```

第一次会隐藏输入 DeepSeek key，并将它存为只有当前用户可读的文件。Harness 不购买额度，不更改账户支出限额。项目必须是已有已保存版本的 Git 仓库。有未保存的源码改动时，会在付费调用之前停止，避免悄悄遗漏你的代码；首次由维护者保存项目版本后即可提交，Harness 不覆盖或替你提交原目录。系统自动识别 `make verify`、Python unittest 或 pytest 等现有测试。项目依赖需要先按项目自己的安装说明准备好。无法识别的项目，由维护者一次性设置 [配置示例](config/factory.example.json) 中的测试命令；日常用户不用选测试、调 Agent 或写 reviewer prompt。

已经有私有 token 文件时可用 `--deepseek-token-file /绝对路径`；文件须为当前用户所有、权限 `0600`。已有独立官方 Codex 认证目录时可用 `--codex-home /绝对路径`，无需改动原来的 Codex 配置。

已有 GitHub Actions 的项目先安装 `gh` 并运行 `gh auth login`。Setup 自动识别 GitHub origin 和工作流。任务会将候选版本推送到 `factory/...` 专用分支，等待对应 exact commit 的所有配置工作流和 matrix jobs 完成；不会修改 main、合并 PR 或发布。Hosted CI 应使用项目负责人已授权、不会在 `factory/...` 分支自动发布的测试工作流。候选任务不能修改或新增 GitHub workflow 再自行执行；CI policy 变更需要单独授权的验证方式。本次真实验收工作流只做测试，使用只读 token。没有 GitHub Actions 的本地项目，交付会明确显示 `GitHub CI：NOT_CONFIGURED`，不会拿本地 CI 冒充 hosted CI。

```bash
harness factory-doctor
```

Doctor 检查本地配置，不产生 inference 费用，也不声称已经验证模型访问权。真实任务另行记录 Provider、模型、profile 和结果证据。

## 提交需求，查看进度和交付

```bash
harness submit "给计算模块增加平均值功能。空输入返回 0，保留小数，不影响加法。"
harness status
harness delivery
```

提交后会自动运行。原项目保留原分支和文件，开发在独立 clone 的候选分支中进行。多个任务都有自动生成的任务编号；省略编号时，`status`、`delivery`、`resume` 和 `cancel` 选择最近提交的任务。要查看其他任务，附上它的编号。

`PLAN / IMPLEMENT / TEST / CI / REVIEW / REWORK` 表示系统正在规划、开发、测试、跑 CI、审核或修复。`READY_FOR_USER_ACCEPTANCE` 表示候选版本已经通过配置要求的门禁，可以由你验收；不是已经合并或上线。

交付界面给出候选源码目录、exact commit、测试、两家审核、资源使用和证据入口。需要完整记录时：

```bash
harness delivery --json
```

高级用法保留：`submit --repository ... --request ... --acceptance ... --constraint ... --scope ...`。不同项目可用独立 `--config` 和 `--state-dir`，不需要用户自己建分支或安排 agent。

## 关闭终端、中断和取消

中断后重新打开 Harness：

```bash
harness status
harness resume
```

系统复用已经完成且校验通过的证据，不会重新执行已完成的模型调用。控制器崩溃后，独立 watchdog 仍限制正在运行的子进程。

官方运行器使用独立的官方 OpenAI transport 配置：HTTP/SSE 自动重试、无限连接重试和 WebSocket fallback 均关闭；登录被明确拒绝后的官方认证刷新不属于未知 inference 重发。

如果请求已登记但无法证明最终结果，状态为 `UNKNOWN`，任务和 reservation 保留；`resume` 不会盲目重发。它表示系统没有足够证据继续，并不表示代码通过。普通测试失败和 reviewer findings 会自动返工；不要不断复制下一条 prompt。

停止一个任务：

```bash
harness cancel
```

取消会停止当前受控进程，保留所有证据和已发生/未知的费用记录；被取消的任务不能继续付费运行。`Ctrl+C` 也会中断当前执行，但任务账本仍保留。新需求使用新的 `submit`，不会改写旧任务。

## 怎么批准最终 merge

先验收 `harness delivery` 显示的候选版本，再显式记录批准：

```bash
harness approve 任务编号 --action merge --head 交付显示的完整commit --reason "已验收，批准这个版本"
```

该命令重新校验目标和证据，只记录对这个 exact HEAD 的批准。最终合并由项目现有人工合并流程执行。Harness 没有自动 merge/release 执行器，模拟任务不能获得正式批准。

## 怎么看资源使用和预算

`status` 和 `delivery` 显示执行次数、已观察的 token、未知 usage 及其永久保留额。金额没有真实遥测时明确为 `UNKNOWN`；不猜订阅价格，不把失败算成免费，不回填历史 UNKNOWN。

第一次付费 dispatch 前，Factory 会记录 `PREPAID_PREFLIGHT`：只读取提交时的 baseline 和配置，不运行项目测试、Make、Docker 或 Provider 资格请求。独立审核的全库文本超过 `max_context_bytes`、缺少门禁可执行程序、明确依赖 Docker daemon 的门禁，以及 hosted workflow 不接受 Factory 候选分支 push 等已知问题标为 `HARD_BLOCKER`，以 `BLOCKED_PREFLIGHT` 停止，执行次数与 token 预留均为零。基础文本即使可读也不截断；扫描最多读取 64 MiB blob，有时间限制，不完整的扫描只提供下界。

`WARNING` 表示当前 baseline 没发现该项明确障碍；`UNVERIFIED` 表示无法静态确定。`NO_KNOWN_HARD_BLOCKER` 不代表环境 READY 或交付 PASS。未来 diff 的 `max_review_bytes`、实施后的上下文、复杂 Make/CI 过滤、包和服务、远端权限以及项目自己的 receipt 合同仍需后续验证。YAML 使用 PyYAML 安全解析，重复键和无法理解的配置保持未验证；预检不执行仓库脚本，也不自动 fetch 缺失 Git objects。

只有因预检阻断且从未产生付费 operation 的任务，才可在环境修复后通过 `resume` 重新预检。每次结果追加记录；原授权、scope、提交时间和预算使用量均不重置，UNKNOWN 不重发。Make 的 `.DEFAULT_GOAL` 只支持普通字面目标；`.ONESHELL`、忽略错误和不支持的 Shell 模式（包括 `bash -n`）保持 UNVERIFIED。Makefile 静态读取最多 512 KiB，workflow 仍为 256 KiB，超限不声称已验证。仅接受 tag push 的 workflow 则明确阻断当前候选分支发布路径。

Setup 默认选择 standard 授权；小任务可在首次 setup 时选择 `--size small`，较大项目可选 `--size large`：

| 授权 | 最多执行次数 | 每次 token admission | 总 token admission | 最多开发/返工轮数 | 总时长 |
|---|---:|---:|---:|---:|---:|
| small | 16 | 180,000 | 2,880,000 | 3 | 2 小时 |
| standard | 35 | 240,000 | 8,400,000 | 5 | 6 小时 |
| large | 54 | 300,000 | 16,200,000 | 7 | 12 小时 |

这些额度按规划、最多 4/8 个实施任务、双 Provider 全量复审、返工和有限 schema recovery 设计，供系统在任务内自行分配；不是每调用几次就找你确认。一次执行指一个 Codex turn 或一个 DeepSeek 请求，Codex turn 内可能包含多次原生模型/工具交互。Setup 不产生模型费用。

每次 dispatch 之前预留 per-run token capacity。已返回的真实 usage 用于后续 admission；UNKNOWN 永久保留整次额度。失败 turn 的 usage 可能只是已完成响应的部分遥测；它会如实保存，并额外保留未完成执行的完整 reservation，不据此退还额度。调用次数、总时长、返工轮数和预算授权不可自动提高。新配置不能扩大旧任务 authority；历史 12/12 的耗尽任务保持原记录。

PLAN 另有更小的执行阈值：`min(原 per-run 上限, 32,000 tokens)` 和 `min(当前执行截止时间, 120 秒)`；旧的仅计次数配置也有这项 PLAN 限制。它复用 Codex native rollout budget、token usage 遥测、独立 watchdog 和已有 proxy admission，不增加执行次数或新的预算授权。规划指令要求定向搜索、小段读取和尽早返回有界计划。部分 usage 超出 PLAN 阈值时立即停止后续派发，operation 仍为 UNKNOWN，原授权的完整 reservation 原样保留；不因 PLAN 阈值变小而退款或重发。

Codex 自己的 native rollout budget 限制采样循环，控制器同时检查包含 cached input 的 token 遥测，并有独立进程/时长限制。Token admission 是本地调度上限，Provider 一次已发出的响应在收到 usage 时可能越过阈值；发生这种情况会保留真实超额并停止，不能交付成功。它不是精确美元扣费保证；要求严格金额封顶时，使用 Provider 账户支出限额。Harness 不会自行调整这个外部限额。

官方将 native rollout budget 标为开发中的功能。本地离线协议测试验证已安装 Codex 接受这些配置；没有运行模型来证明物理 token 硬帽。进程终止也不能撤回 Provider 已收到的请求。

## 出错时最少要理解什么

只需看状态和原因：

- `READY_FOR_USER_ACCEPTANCE`：可以验收候选版本，还没有合并。
- `UNKNOWN`：证据或请求结果不明确，没有 PASS，也不会重复付费请求。
- `BLOCKED_BUDGET / BLOCKED_LIMIT`：授权额度或返工次数耗尽，系统已停止。
- `BLOCKED_SCOPE`：变更超出授权范围、目标/工作流不符或上下文太大，系统已停止。
- `BLOCKED_PREFLIGHT`：第一次付费请求前发现明确容量、环境或 CI 障碍，尚未派发。
- `CANCELLED`：取消请求已生效，旧账本保持不变。
- `WAITING_PRODUCT_DECISION`：真正涉及产品方向的歧义，需要你做产品决定；普通技术选择由系统处理。

执行命令只有交付 READY 才返回退出码 0；停止或 UNKNOWN 返回 1。`status` / `delivery` 是只读查询，正常读取返回 0；配置错误返回 2。

遇到停止状态，把 `harness delivery --json` 的报告交给维护者即可；不需要阅读内部架构文档。Provider 登录失效、模型访问权、GitHub 权限或账户限额，需要账户持有人处理。

## 边界与历史

双审核使用不同 Provider、不同线程/checkout，不交换彼此结论。审核覆盖完整 `base..head` diff。大型源码上下文、二进制变更和变更的 submodule 不能通过当前独立文本审核时，明确停止，不截断或假装通过。live tests 的源码/Git metadata 为只读；依赖或构建产物需要项目支持临时目录。

Reviewer V2 的 chunk/group/synthesis 和旧 qualification 路径已 deprecated；只用于历史读取和兼容回归。旧 ledger、receipts、UNKNOWN 和 support artifacts 不迁移、不删除、不退款。旧 v1 `run/resume` 需显式 `--legacy`，禁止自动合并。新项目不需要了解旧平台。

[架构说明](docs/FACTORY_ARCHITECTURE.md) · [历史迁移验证](docs/FACTORY_VALIDATION.md)

维护者的本地验证：`make verify`。真实验收脚本 `scripts/factory_acceptance.py` 必须显式提供新输出目录和配置，CI/unit tests 不会发起付费模型调用。
