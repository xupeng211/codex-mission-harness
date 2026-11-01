# 委派工具的任务专属临时空间

本边界来自Owner在2026-11-01的新决定，从本轮修复起生效：开发Agent可以使用本任务明确分配的临时空间；其他任务或用户的临时文件没有授权；结束后只能清理自己的资源。不回填旧授权，不更改旧调查、审核或PASS的含义。

## 授权区域

- 开发工具可依现有scope修改准确候选源码，并读写控制层分配的专属临时目录。
- 普通宿主`/tmp`、调用者的`TMPDIR`、其他任务的专属目录及其他候选没有额外读写授权。
- 只读planner/reviewer保留最小仓库/运行时只读边界，不分配可写临时空间。
- Factory原有Controller、证据、预算、原库和认证不可访问；scope及Git元数据只读，网络禁用、审批拒绝。工作区的`.agents`、`.codex`和`.aws`也保持只读。

## 实现与绑定

沿用已有只读lane的最小runtime/repository配置，开发仅对准确cwd和专属临时目录增加write。两个角色都不继承`:workspace`，因此不会带入系统`/tmp`或调用者`TMPDIR`的宽权限；不靠Agent自觉，也不靠只设置环境变量。

`TaskTemp`由可信适配器调用固定`/tmp`下的`mkdtemp`创建0700独占目录，不接受候选传入的目录。目录不在Git工作区或Controller/原库/auth等受保护根内。身份包含绝对canonical路径、准确worktree、随机permission profile、uid、device/inode和mode；持有目录fd至清理结束，避免inode复用伪装。使用、thread/turn及同会话复用前重新核对，替换、软链接、mode或绑定不一致即失败。

进程实际`TMPDIR`、`TMP`、`TEMP`和thread的shell环境均设为该准确目录。权限表一次完整生成，包含原保护规则和这个准确write路径；不重复覆盖完整filesystem表，不重新开放父目录。只读不增加这些变量或写授权。CLI不支持准确配置时启动失败，没有宽权限回退。

Factory官方路由、CLI proxy开发路由，以及legacy `AppServerCodex`使用同一临时目录能力。Proxy的认证、relay及既有route qualification规则不变。Legacy也使用最小的准确workspace/runtime配置，不再继承宽宿主读或临时写；缺少最小依赖的命令明确失败，不扩大读取范围补救。

## 生命周期、证据与恢复

资源属于一次constructor绑定的委派会话；同一任务的实施/返修会话可复用同一目录，但每次核验身份。成功、异常、启动失败以及取消后的既有`close`/`finally`清理它。不会从磁盘接纳旧临时目录，不从模型输入或历史记录指定路径，也不按公共前缀扫描删除。

Factory在控制层的操作transcript旁保存不可变`.temp.json`分配身份，其hash加入原操作证据。清理尝试追加至`.temp.cleanup.jsonl`；同会话最终关闭时，Controller追加`agent_temporary_cleanup`事件，绑定任务、原分配操作、分配原件与清理原件的路径和hash。非复用操作的清理日志随分配身份可核对，任务专属目录内容不作为正式审核证据。

清理使用下述原子认领机制，不能仅凭验证路径或`rmtree`的防软链接检查决定归属。目录内指向其他任务的软链接只删除链接。根身份、私有mode、终止或清理证据无法确认时抛出明确错误，不删除替换对象，不宣称清理成功。同会话清理失败保留runtime归属，Controller任务为UNKNOWN；恢复被持久失败事件阻断，不重放任务或接纳其他资源。Owner需要核对保留的准确身份后另行处置，不能删事件来绕过。

Controller遭SIGKILL或宿主崩溃时可能来不及清理，目录及分配记录会保留；没有自动扫前缀“回收”。原有RUNNING/UNKNOWN与no-replay规则继续适用，不能从重启推断旧资源已清理。新建合法会话只创建新目录，绝不借用旧目录；未确认资源需要按准确分配身份处置。此限制不同于正常取消/异常的finally清理。

### AppServer停止依据

Factory（官方/代理、复用/非复用、只读/开发）及legacy AppServer的启动都经过一个专用Linux监护进程。它在派发前启用并核验subreaper和pidfd能力；与Controller通过不向工具继承的私有socket通信。执行身份包含随机execution id、准确worktree、permission profile、TaskTemp原身份、操作transcript及Factory任务/run绑定；监护进程的PID、启动时刻、父进程、uid、session/group和pidfd与该分配一同保留。可信监护代码不得位于委派工作区内。

沿用owned-client的原始身份核验及`waitid(WNOWAIT)`原则，但不照搬“原进程组已空”的完成判断。AppServer或watchdog可以先退出，后代可以`setsid`或double-fork；专用subreaper仍是它们的收养祖先。关闭时只枚举监护进程自己的直接子进程，通过pidfd向尚未回收的准确对象发送TERM，必要时KILL；父进程退出后重复处理被收养的后代。只有`waitpid(-1, WNOHANG)`返回内核`ECHILD`，才确认这个启动子树没有剩余子进程。它不扫描全系统PID，不向历史PGID发组信号，也不信任一次`Popen.poll()/wait()`作为整棵子树停止证明。

顺序是：取得绑定的ECHILD回执、追加停止诊断、允许监护进程退出并回收、关闭stdio、按原目录身份原子清理TaskTemp、追加成功清理凭据，最后释放runtime归属。初始化前已登记执行归属，因此取消也覆盖初始化阶段；派发前已取消则不启动。Factory的`.process.jsonl`只是追加诊断，不能替代清理原件。新的native runtime记录绑定原执行身份，清理原件中的`process_stop`必须与之及任务/操作/目录匹配，后续report/run继续核对原件hash和绑定。

监护进程被提前poll/wait回收、启动身份不符、控制通道断开、证据无法写入或停止无法确认时，关闭返回UNKNOWN，不删TaskTemp、不写成功凭据，保留server/current_process及必要runtime归属。失败是sticky的；重复close或run不重试派发，不用较晚成功遮盖早先UNKNOWN。Controller重启不从历史PID/PGID重建执行归属或重放操作。原操作失败、进程停止确认、目录清理确认是三个独立事实；EOF/超时即使安全清理，也仍是原操作失败。

本机制要求Linux的subreaper、可核验的`/proc`进程元数据及children、pidfd信号、WNOWAIT和Unix私有socket能力；缺失即阻断，不退回单进程/进程组关闭。它依赖可信监护进程单线程独占其子进程的创建、停止和回收，Controller不提前回收监护进程，宿主可信代码不篡改监护代码或控制通道。ECHILD只证明该专用收养子树已结束：不涵盖工具通过既有外部服务另行委派的进程、具有特权的重归属/调试者或攻击Controller的宿主同uid程序。普通fork、double-fork及session/group变化不脱离这个子树；不能证明仍在该边界内的情况保留UNKNOWN。现有禁用外部服务、插件、网络及权限规则继续适用，没有因此新增授权。

停止阶段TERM宽限为0.25秒，总停止期限5秒，协议消息最多65536字节，信号与回收诊断合计上限128项。能力、权限、期限或证据容量不足都返回UNKNOWN并保留资源/归属，不通过截断证据或不安全的备用删除取得成功。这些是本地清理的边界，不延长任务执行授权或改变费用结算。

### 清理对象身份及并发边界

Controller先创建一个不向Agent授权的独占0700认领父目录。通过Linux `renameat2(RENAME_NOREPLACE)`、已打开的父目录fd，将公共名字处的对象原子移入该私有目录，再核对被移入对象的原始device/inode、uid、mode及适用的分配标记。只有匹配后，才在私有父目录fd下执行防软链接的`rmtree`。公共名字在核验后被替换，捕获的替代对象不会被递归删除；尽可能用不覆盖目标的原子rename归还。归还受阻时保留在认领目录，错误及追加的`.claims.jsonl`记录准确位置。该日志只是清理计划，不能充当成功凭据，也不授权恢复流程接纳新路径。

并发假设是：AppServer委派客户端已按上述原执行身份取得停止证明；沙箱只获得原TaskTemp准确路径，不能访问新认领父目录；可信Controller及宿主代码不修改这个私有父目录，也不把外来对象注入所属目录树。允许公共源名字发生并发替换。删除后公共名字若重新出现，保留新对象并返回UNKNOWN。控制层被中断在认领途中时，也不扫描或猜测归属；保留计划和资源供按准确身份处置。

支持范围为Linux、具有`renameat2` libc入口及`RENAME_NOREPLACE`支持的同一文件系统，Python的fd相对`rmtree`及防软链接能力（本轮为Python 3.14）。平台、文件系统或原子原语不支持时停止清理，返回UNKNOWN；不退回按公开路径删除。这些假设不涵盖可任意改动Controller私有资源的宿主同uid程序。

容器验证的version 3生命周期记录在首次外部派发前持久保存临时目录的原始身份、随机nonce及任务/操作/target/container绑定；目录内0600分配标记防止目录消失后inode复用被误认。恢复只清理准确原对象，并使用同一原子认领机制。version 2或更旧记录没有原始身份，缺失目录、标记或任一绑定不符均为UNKNOWN，保留资源；不从路径、owner或0700推断归属，不重放验证补证据。

容器验证的恢复还必须核验同操作的`.container.clients.jsonl`原件。该Controller私有追加记录绑定生命周期原字节SHA256、任务/操作/target、原目录身份和nonce、原执行令牌及Controller身份。每个会访问验证目录的本地客户端（源码/策略查询、Git准备、镜像查询、依赖create/cp、服务启动/就绪查询及主验证）在Popen前持久写入意图，启动后登记PID/starttime/父进程/UID/PGID/SID，既有owned-client机制确认原组停止并回收leader后才持久写入停止事实。最后一次查询完成后先关闭派发阶段，再写入全记录hash和客户端数量；完整顺序和每个停止项都必须成立，较晚成功不能覆盖较早未确认项。日志独立限64 KiB，容量或持久化失败不能继续派发或清理。

恢复先只读核验这份封闭证明，再处理精确容器及原目录；容器不存在、COMPLETE、目录身份正确都不能代替本地停止依据。启动意图后中断、身份未登记、停止未确认、停止后凭据未落盘、未封闭、原件缺失/损坏或绑定错误均保留UNKNOWN和现场。旧version 3记录缺少这份证明也不能自动清理。已结束操作将该原件hash加入不可变操作证据；report、run/resume和已确认清理的跳过路径仍重验原件、hash和绑定。恢复只追加结果，不修改旧操作/生命周期/日志，不接管或盲杀旧PID/PGID，不重放操作补证据。

这只持久化既有Linux `waitid(WNOWAIT)`所有权机制能证明的普通同session/进程组停止事实，不扩展为任意daemon或主动setsid逃逸后代的停止保证。依赖Controller私有证据目录、串行派发和客户端遵守既有进程边界；无法取得该既有证明时不封闭。重启后的新Controller不推测进程状态，也不新增杀旧进程的能力。Docker inspect/rm等收尾命令不以验证目录为cwd、不传递快照/凭据文件路径；原有精确容器所有权检查保持。

`report`、`run`恢复入口及最终关闭后的交付判断会重新核验本任务每项分配和全部相关清理凭据：原始操作证据、原件hash、准确路径及目录身份、任务与操作绑定。较晚的成功事件不能盖过较早失败或丢失的原件。凭据缺失、改动、串任务或身份不符时输出UNKNOWN，不保留READY，不重跑开发、审核或验证来补写凭据；既有操作记录保持不可变。

旧的最终关闭事件若缺少这里要求的任务/操作及分配原件绑定，也保守报告UNKNOWN；不改写旧事件或替旧任务补发成功。缺少身份或凭据的历史任务需要按保留证据另行处置，升级本身不解除原有UNKNOWN。

## 无模型开发验证

正式回归通过拦截产品AppServer启动及模拟initialize/execute捕获原argv/cwd/env，再用原生CLI `sandbox --permission-profile ... --cd ...`执行fixture脚本，不启动真实AppServer/Provider/model。覆盖`/tmp`、`/home`的开发/只读，另验证legacy、可选命名配置和模拟proxy relay的配置分支；真实Provider、代理上游或AppServer线程未在该验证中运行。

脚本逐项捕获异常并flush，网络socket失败不丢文件结果；宿主前后核对标记内容、hash和mode。ENOENT单独记为不可见，用宿主存在性和mountinfo证明映射隔离，不伪称EACCES。生命周期测试覆盖成功/失败/取消、复用、身份替换、软链接、启动失败及UNKNOWN恢复不重放。
