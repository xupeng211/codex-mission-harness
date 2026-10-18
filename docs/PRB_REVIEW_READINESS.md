# PR B：独立审查准备

E2E_08 已真实完成 `LOCAL_CANDIDATE_READY`，可以进入最终独立代码审查。
独立审查尚未执行；本轮仅修复 CLI 退出状态并整理证据，没有新增模型派发或远端动作。

## 真实验收与本轮只读复核

E2E_08 运行于 Harness `9ecc0a18977e9537bdd293e1352ec25583e8b2df`。
真实 Agent 为官方 ChatGPT OAuth 渠道的 `gpt-6.1-sol / high`，
1 thread、1 turn，正常 `completed`，无 fallback，未触发返修。

业务候选基线为 `14633c3ca99309a1a4d6d9b5b107f2c0b8c98342`，
最终 HEAD 为 `b01f7fd35253e41673cac12ff7ecfa5a36f1f082`，
Tree 为 `b51a9ac36a80d0ac1e6660a33d3d7f9025dec7fd`。
Agent 修复 `valid_triple()` 的必需键检查，新增缺 home/draw/away 且带 extra 的三个回归。
Controller 固定 digest Docker 环境的 `make verify-targeted` 实际通过：
Python 11 项、JavaScript 48 项，静态/格式检查通过，exit 0，cleanup COMPLETE。

累计观察 138,294 tokens，用量完整；输入 135,937（含 cached input 103,680），
输出 2,357。总执行 90.305 秒，其中原生 turn 52.352 秒、QA 32.714 秒。
最终货币费用 UNKNOWN，不宣称物理 token 或货币费用绝对封顶。

本轮用 `mode=ro&immutable=1` 读取封存数据库，先确认 WAL 为空，避免 SQLite
写锁或 SHM 更新；核对数据库、交付事件、操作/原始证据哈希、结构化报告、原生 usage、
授权、Git/scope/full diff、可信 QA 目标与完整日志，均一致。
没有用当前版本打开历史 Factory，也没有重跑 E2E_08 或 QA。

原始证据：`/home/xupeng/.local/state/codex-factory-prb-real-e2e-08/`。
本轮复核及上传材料：
`/home/xupeng/.local/state/harness-delivery-evidence/PRB_REVIEW_PREP_20261018/`。

## CLI 退出码修复

历史 E2E_08 的 `cli_exit_code=1` 保持原样。
根因在 `factory_cli.main()` 的最后退出条件：它只接受
`READY_FOR_USER_ACCEPTANCE`，遗漏了已经正式生成的 `LOCAL_CANDIDATE_READY`。
执行结果已打印，`factory.close()` 已完成，之后 CLI 自身抛出 `SystemExit(1)`。
外层调用器只记录子进程原始退出码，没有把成功改写成失败；没有收尾异常证据。

最小修复只将 `LOCAL_CANDIDATE_READY` 加入成功状态集合。
没有改 Factory 的验收标准、异常处理、预算、授权或状态生成。
确定性回归覆盖公开 `harness` 入口、直接 Factory CLI、submit/run/resume 及别名，
并确认 UNKNOWN、阻断、未完成、缺失状态、执行错误和 cleanup 错误仍返回非零。
只读 status 保留原有退出语义。

捕获的真实 E2E_08 报告通过临时目录和 mock Factory 在实际 CLI 子进程中复现：
修复前 exit 1、修复后 exit 0；输出 JSON 逐字段相同，close 均完成，模型派发为 0。
该复现仅回放结果对象，不打开或执行历史 Mission。

## 完整审查范围与风险

完整补丁以本地 `origin/main` 指向的已合并提交
`390b8439b98c76d59e61c74f905531664a40318c` 为基线，包含此前全部 PR B 变更和本次修复。
没有远端 fetch，不能据此声称远端 main 在此后从未变化；提交审查时应保留此准确基线。
上传包提供基线及最终源文件快照、完整补丁、修改清单、测试日志及 E2E_08 精简原始证据。

仍需独立审查的重点：

- 正常完成与 usage 完整性、同 thread 返修的预算和授权边界。
- 候选 Git/scope 和 Controller 独立 QA 的证据绑定。
- UNKNOWN 保留、异常停止及 CLI 不掩盖失败。
- 原生 App Server 版本兼容性，以及同 OS uid 下本地证据保护的现有信任模型。

E2E_08 首次 QA 通过，真实自动返修没有被实测；其覆盖来自离线协议、原生零推理及
确定性编排测试。CLI 修复后未新增真实 E2E；验证来自捕获结果复现及完整本地回归。
当前候选不是合并、发布或生产验收，也没有执行独立模型审查。
