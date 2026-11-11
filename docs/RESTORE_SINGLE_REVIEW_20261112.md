# 恢复 Harness 单独立审核交付主线（2026-11-12）

本轮角色：EXECUTION_CONTROLLER；交付是本地待独立审核候选和下一轮执行提案。
Owner 本轮禁止真实模型、业务开发、push、PR、Merge、部署；下文不构成执行批准。
第二审代码、测试、分支和历史证据保留；目录清理、重装、DeepSeek/Antigravity 排障暂停。

## 项目和版本事实

开始写入前核对：

```text
PROJECT_ROOT=/home/xupeng/codex-mission-harness
INITIAL_BRANCH=main
INITIAL_HEAD=5d5d441bbac8a603cd189fb543809fb7718ce937
INITIAL_DIRTY_STATE=CLEAN
BASE_SHA=5d5d441bbac8a603cd189fb543809fb7718ce937
WORK_BRANCH=fix/restore-openai-single-review-20261112
```

Harness 根和上级目录无 AGENTS.md，`.agents`/`.codex` 无附加文件。
已读取当前 README、`FACTORY_FOOTBALLPREDICTION_CONTRACT.md`、阶段 2 合同及实际配置/调用链。
Harness 本地 origin/main 停在 `6db80276361fb74dd7272e70a3577eabcc978fc7`；
只读 GitHub ref 查询确认远端 main 是 `5d5d441bbac8a603cd189fb543809fb7718ce937`。
没有 fetch、改远端引用或 push；本次以已经匹配远端的完整本地 HEAD 为基线。

FootballPrediction 正式入口始终是 `/home/xupeng/FootballPrediction.clean-dev`：
branch=main，HEAD=origin/main=`93cef9a02ece47ac4450bb696e8671af19022b8d`，工作区干净；
只读 GitHub ref 查询也返回该 SHA。本轮未写该仓库。
已读取该入口的 AGENTS.md、docs/AGENT_WORKFLOW.md（含 V1）、README canonical 入口、
能力索引及当前 milestone/status；其他历史目录不作为当前项目。
#1957 及此前已完成交付保持 DONE，不重做、不降级历史结论。

第二审分支 `feat/antigravity-second-review` 仍指向
`ea7a566952b76c78ee82b1476cd89e07de8648bc`，该 worktree 工作区干净；没有切换、合并或修改它。

## 能否直接复用

基线通用 Factory 的 `independent_review_required=false` 实际保留一名 OpenAI reviewer，
但 FootballPrediction 项目模式拒绝该配置，且 canonical admission、final gate、publish
仍硬编码双审。因此不能把通用开关直接当作合法的 FootballPrediction 单审入口。

本候选增加一个明确配置值 `review_mode=single_openai`，仍要求
`independent_review_required=true`；profiles 只能是 developer/reviewer。
省略 review_mode 或设为 dual 保持原双审；失败时不切模式，不接受隐藏第二岗 profile。
该选择属于既有 policy identity，不能借恢复任务改写历史策略或重用另一模式的交付。
默认 dual 的 target/policy 输出保持原字段集合，不给旧交付增加单审字段导致其身份失效。

复用原 Factory.operation、runner、receipt validator、review feedback、rework、checkpoint、
测试、PR/CI 和 merge-ready。单审不读取 DeepSeek token，不做 DeepSeek 分块 admission，
不派发第二岗，不保留第二岗 operation/token reservation，也不制造第二岗 PASS。
JSON 状态为 REVIEW_MODE=single_openai / SECOND_REVIEW_STATUS=NOT_ENABLED，普通状态也显示中文。

单审必须由可信 BASE 的原 required_backends 和 eligibility registry 接受 Codex；
原 task/path classifier 继续约束等级，NORMAL 不能伪装高风险路径，STRICT 不能掩盖
CRITICAL 路径。CRITICAL 始终拒绝单审。试点仅允许精确 authorized_paths，不给目录通配授权。
STRICT 保留实际 verify-strict 成功的发布门槛。本轮不修改 FootballPrediction 的审核权威。
最终门禁通过 adapter 已有 selected-backend=codex 路径明确选择；双审继续无 override。

开发与审核仍分别启动执行上下文；canonical reviewer 在原 detached/read-only 隔离现场，
读取需求、完整 BASE→HEAD diff、scope 和必要源码，不消费 builder 的 PASS 或测试结论。
同次整树证停、原件哈希、模型 pin、scope/HEAD 绑定和独立 consumer 均保留。
修复产生新 HEAD 后旧审核不再放行；所有 finding（包括 P3）仍进原 Factory 返工 barrier。
测试、review、本地 PR profile、真实远端 required CI 分别记录。
输入绑定/范围可达不证明模型实际逐行读完或语义审查完备。

## 离线验证和局限

新增用例连接原 Factory 入口：有效单审→finding反馈→返工→新 HEAD 复审；无效、缺字段、
NO_VERDICT、旧 HEAD 均 UNKNOWN 且不重派；第二审显式派发被拒绝，数据库无第二审操作/预留。
预检取消未启用 provider 的授权阻断，缺真实容器/发布条件仍阻断。
原 STRICT/CRITICAL 与错误 NORMAL 路径的拒绝保持。

真实 LocalRuntime 监督器、runner、validator 的集成只替换模型/认证为原 fake-backend，
不调用真实模型。final consumer 的远端结果明确为 double，不构成真实 PR/CI 或正式审核。
既有固定合同回归需要 `a65464d1e5de498a072ed9a8fdf69ce46bcc04c5`：
从正式仓库的本地 Git 对象生成 `build/footballprediction-contract-a65464` 只读测试依赖，
它只供原测试的固定合同验证，不是当前 FootballPrediction 入口。
另将当前 `93cef9a02ece47ac4450bb696e8671af19022b8d` 的 scripts/schemas 提取到
测试自清理 fixture，跑同一单审 runner/validator/final bridge 和分类反例：2 项通过。

最终本地提交及完整离线结果见本记录的“最终验收记录”。
本轮是实现者检查，**没有独立审核结论**。下一次真实业务试跑不能替代 Harness 补丁的独立验收。

## 下一次真实小任务提案

任务 ID：`FP_TEAM_URL_TRAILING_PATH_FIX_20261112`。
问题：`src/utils/teams/url_tools.py::extract_team_names_from_url` 的路径正则未锚定末尾，
会把多余子路径当作有效比赛。这与 #1957 的空队名问题不同。
依据是当前函数、既有 `tests/unit/test_team_url_tools.py` 的 supported/unsupported URL
与 query/fragment 约定，以及当前源码只读复现；没有发明新联赛、队名或采集需求。

当前实际结果：

| 联赛 URL 后缀 | 当前结果 | 提案验收结果 |
| --- | --- | --- |
| arsenal-chelsea | Arsenal / Chelsea | 保持 |
| arsenal-chelsea/ | Arsenal / Chelsea | 保持 |
| arsenal-chelsea-AbCd1234?next=/other/path#summary | Arsenal / Chelsea | 保持 |
| arsenal-chelsea/extra | Arsenal / Chelsea | None |
| arsenal-chelsea-AbCd1234/extra | Arsenal / Chelsea | None |
| arsenal-chelsea// | Arsenal / Chelsea | None |

只读复现先将正式入口 teams 包源码装入 dev 容器的内存 importer（未借用容器内旧项目源码），
退出码 0，后 3 项均重现误识别。既有 154 项 URL 测试在只读挂载正式入口的已有 QA
镜像中通过；`--noconftest` 用于这个纯函数定向检查，未读取 .env 或连接 DB，不能替代正式 profile。
首次尝试引用运行中 dev 容器的已删除 image 失败；改用下列已存在 QA image，无 pull/build/修复环境。
首次 pytest 只读根缺临时目录而失败；仅给容器 /tmp 增加 64MiB tmpfs 后 154 项通过，源码挂载始终只读。

预期：最多一个可选尾部 `/`；query/fragment 中的 `/` 不参与路径判定。
非法多余路径返回 None。带/不带 match ID、多词队名、query/fragment 和 #1957 空队名
回归必须保留。不要顺手改 host/scheme、ID 识别、联赛范围、智能分词或 legacy semantic_refiner。

允许修改仅三项：

```text
src/utils/teams/url_tools.py
tests/unit/test_team_url_tools.py
docs/agentic/missions/FP_TEAM_URL_TRAILING_PATH_FIX_20261112.json
```

scope task_type=source-code，workflow_class=STRICT（原路径分类，不伪称 NORMAL）；
authorized_prefixes=[]，排除 DB/资金/权限/生产/模型/采集与工作流权威。
新增 mission 是原 schema 的普通范围合同，不是新增审核系统。
下面是供下一轮批准的 scope 内容草案；原 canonical prompt 会直接包含这些需求约束。
它没有附 Owner approval_id/expiry，也没有作为业务候选写入 FootballPrediction。

```json
{
  "schema_version": "agentic-mission-scope/v1",
  "mission_id": "FP_TEAM_URL_TRAILING_PATH_FIX_20261112",
  "task_type": "source-code",
  "workflow_class": "STRICT",
  "authorized_paths": [
    "src/utils/teams/url_tools.py",
    "tests/unit/test_team_url_tools.py",
    "docs/agentic/missions/FP_TEAM_URL_TRAILING_PATH_FIX_20261112.json"
  ],
  "authorized_prefixes": [],
  "excluded_paths": [],
  "excluded_prefixes": ["database/", "src/database/", "config/", ".github/", "scripts/devops/", "scripts/ops/helpers/"],
  "excluded_tokens": [],
  "protected_invariants": [
    "比赛 slug 后最多允许一个尾部斜杠；多余子路径或重复尾部斜杠必须返回 None。",
    "保留有/无 match ID、多词队名、query/fragment 的既有合法行为；query/fragment 中的斜杠不作为路径。",
    "保留 #1957 空队名拒绝行为；不得顺手更改 host、scheme、match ID 启发式、联赛范围或智能分词。",
    "增加非法尾部路径的回归，并保留当前 154 项 URL 测试；原 verify-strict、verify-pr 和 exact-head 独立 Codex review 必须通过。"
  ],
  "forbidden_side_effects": [
    "禁止真实网络抓取、正式数据/DB 写入、迁移、资金或权限变化、训练、预测、模型激活。",
    "Builder 禁止 push、PR、merge、deploy；仅 Controller 在本任务单独授权内处理同一 PR，Owner 决定最终合并。",
    "禁止修改审核/CI/治理权威、启用第二审核员、静默换模型、扩大 scope 或增加预算。"
  ]
}
```

Source change 只有这个纯解析函数及必要测试；不写正式数据、不迁移、不抓取、不训练/预测。
无长期能力/入口/里程碑/数据模型/授权变化；下一 PR 的七项 Documentation Impact
应逐项声明 NO 并说明“仅拒绝比赛 slug 之后多余 path，未改变这些边界”。
若原 preflight 判定必须其他合同回流，停止并交回差异，不能扩大范围修改治理。

## 执行安排、费用和停止条件

配置草案：`config/factory.footballprediction.single-openai.example.json`，不覆盖用户默认配置。
采用 project_container + project_delivery 路线；不混用 trusted_validation/project_pr_ci，
后者的发布时序和授权合同不同。现有默认 operator config 仍是通用双审配置，不可直接运行试点。

开发/规划：gpt-6.1-sol / medium / official，使用现有私有
`/home/xupeng/.codex-harness-official`；不使用日常 `.codex` 的 cli_proxy_api 配置。
审核：当前可信项目 pin 的 **gpt-5.6-terra / medium**，由原 canonical runner 选择，
原 `/usr/lib/chatgpt/resources/codex` 和
`/home/xupeng/.footballprediction/canonical-codex-reviewer`。本轮不升级模型或认证。
账号目录及配置存在只证明本地配置，不证明模型访问/额度可用；不可用就停止，不切第二岗或代理。

资源上限直接由现有配置执行：

- max_agent_runs=5（合计规划/开发/返工/审核 outer operations）；max_rounds=2。
- 预期 1 次规划 + 1 次开发 + 1 次审核；有 finding 最多再 1 次返工 + 1 次新 HEAD 审核。
- 原 planner 仍可返回多个小 assignment；没有新增 planner。硬上限是初轮 implement 最多 3 次、
  rework 最多 1 次、review 最多 2 次，且合计含规划不超过 5。预期单 assignment；拆多时同一
  总额不会增加，剩余预算不足即停止，不能承诺仍有完整修复/复审额度。
- 每 outer timeout≤900 秒，mission wall≤7200 秒，完整 diff≤32768 bytes；不截断审核。
- max_run_tokens=120000，max_total_tokens=600000 是逻辑 admission/reservation。
  canonical CLI 内部 HTTP 次数、重试、实际 token/订阅扣额和人民币金额仍 UNKNOWN；不是物理硬封顶。
- 第二审核员调用数和对应预算预留=0。本轮真实模型调用=0、模型新增费用=0。

未来 Owner 如要求“确定人民币≤X”或确定内部 HTTP 次数，本提案不能承诺，应保持不启动。
如接受上述 outer/时长/逻辑预留上限及内部用量/金额 UNKNOWN，须在下一轮明确授权这个准确任务；
不沿用本轮准备工作的授权去收费。Harness 补丁独立验收的模型/费用另算，不挤进业务五次预算。

停止条件：范围扩大、业务语义另议、CRITICAL 分类、canonical 模型/认证/镜像不可用、
输入/证停/回执 UNKNOWN、预算/时限/轮数用尽、源 HEAD 或远端 main 改变、PR/CI 不能证实。
没有无界重试、加预算、换模型、静默双审降级或跳过 tests/CI。已发生 UNKNOWN 的 paid 操作
保留原证据和 reservation，不自动重派。

现有可复用镜像准确 ID：QA `sha256:7c4993ba149012d0336607b90aea855446857f86ac3dd615b8727a4f49e172b3`，
临时 PG `sha256:72b75a9e60891118b5221c08771145c2191987d521ac1ad64d31d7421d15db49`。
本轮确认配置校验通过、两镜像本地存在、开发/审核本地认证配置校验通过（零 inference），
未宣称它们对当前完整 strict/pr profiles 或真实模型访问已验收；下一轮须先通过原
prepaid/container preflight、锁文件/QA 字节及临时服务绑定。没有准备/重装镜像授权。

## 下一轮的具体启动顺序

1. 对本地 Harness 准确候选完整 diff/必要源码进行独立审核，不能用本轮测试或业务试跑自证。
   当前原双审能力/高风险要求不改变；若验收要求额外第二岗而该岗未启用，就保留候选、停止，
   不借此授权 DeepSeek/Antigravity 排障或收费。独立审核找问题则先窄修复，再新 HEAD 独立复审。
2. 固定通过独立验收的 Harness HEAD，使用对应源码的 PYTHONPATH/CLI（不猜已安装 entrypoint）。
   下一轮若 Harness 实现有变，本提案版本失效，需要重新记录差异/验证。
3. 只读刷新正式项目远端 main、origin/main、clean HEAD；仍须等于
   `93cef9a02ece47ac4450bb696e8671af19022b8d`。有变化停止重核，不把旧 base 当最新。
4. Owner 对上述 URL 语义、三路径 scope、五次 outer 上限、费用 UNKNOWN 及同一 PR 创建/更新
   作出明确授权后，才把批准的 scope 精确 JSON 字节、sha256、approval_id、到期时间写入
   原 Factory v2 的 approved_mission_scope。它尚未生成，避免伪造 Owner 批准。
   `mission_scope_file` 必须是本任务路径；objective/acceptance/constraints 使用上文原文，scope
   是上列三路径，省略 delivery_mode（默认项目远端路线），pr_body_template 使用原唯一 PR 模板。
5. PR template 预填 Summary/Scope/Tests/Risk/Rollback、STRICT evidence，provider=codex-cli，
   Reviewed full SHA=`{{candidate_head}}`，Timestamp=`{{review_timestamp}}`，以及本任务 scope 引用。
   证据占位只有 Controller 按实际新 receipt 渲染；模板中的 Result=PASS 只允许在真实 current
   receipt 已验证 PASS 后形成正式正文，模板草案本身不构成审核通过。
6. 配置文件/mission 文件放既有 `~/.local/state/codex-factory/<mission-id>/` 的运行记录位置，
   state-dir 本身必须在 Git 仓库之外。先只运行 factory-doctor 和原只读 preflight；缺条件停止。
   批准后调用：

   ```bash
   PYTHONPATH=/home/xupeng/codex-mission-harness/src \
     /home/xupeng/codex-mission-harness/.venv/bin/python -m harness.cli factory-run \
     /home/xupeng/.local/state/codex-factory/FP_TEAM_URL_TRAILING_PATH_FIX_20261112/mission.json \
     --config /home/xupeng/.local/state/codex-factory/FP_TEAM_URL_TRAILING_PATH_FIX_20261112/config.json \
     --state-dir /home/xupeng/.local/state/codex-factory/FP_TEAM_URL_TRAILING_PATH_FIX_20261112/state
   ```

7. 既有隔离候选分支应是 `factory/FP_TEAM_URL_TRAILING_PATH_FIX_20261112-93cef9a02ece`。
   原 strict 测试和本地 PR profile → current-HEAD 单审 → 必要返工/新 HEAD 全部重验 →
   同一 PR create/update → 真实 required CI → 原 merge-ready → STOP AT OWNER MERGE。
   两个 required check 名称仍以实时 ruleset 为准，不能拿本地 profile 或历史 green 替代。
8. READY 不等于 DONE；Owner 决定最终 Squash Merge，合并后对实际 merge SHA 的 main
   Production Gate 成功才可 DONE。部署不在任务授权里。

## 能证明和不能证明

本轮证明单审选择在原接缝中的离线可行性、负例阻断、返工与 HEAD 新鲜度；
当前真实源码确有提议修复的问题。下一次成功可证明这个有界业务任务通过单 OpenAI
独立审核/返工、真实 PR/CI 后交回 Owner 的完整链路。
若模型没有发现 finding，只证明该次审核通过，不能宣称真实返工发生；返工接缝当前只有离线证据。
不能证明第二审可用、高风险任务可一律单审、任意业务自主交付、物理费用硬封顶或生产效果；
未经 Owner 合并及 main Gate 不证明 DONE。第二审历史记录没有被覆盖成 PASS。

## 最终验收记录

待本地完整验证完成后填写。本候选独立审核状态始终为 NOT_RUN。
