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

Factory在控制层的操作transcript旁保存不可变`.temp.json`分配身份，其hash加入原操作证据。清理尝试追加至`.temp.cleanup.jsonl`；同会话最终关闭时，Controller追加`agent_temporary_cleanup`事件并绑定清理证据hash。非复用操作的清理日志随分配身份可核对，任务专属目录内容不作为正式审核证据。

清理先核对准确对象再使用不跟随链接的fd-based `rmtree`；目录内指向其他任务的软链接只删除链接。根身份、私有mode、终止或清理证据无法确认时抛出明确错误，不删除替换对象，不宣称清理成功。同会话清理失败保留runtime归属，Controller任务为UNKNOWN；恢复被持久失败事件阻断，不重放任务或接纳其他资源。Owner需要核对保留的准确身份后另行处置，不能删事件来绕过。

Controller遭SIGKILL或宿主崩溃时可能来不及清理，目录及分配记录会保留；没有自动扫前缀“回收”。原有RUNNING/UNKNOWN与no-replay规则继续适用，不能从重启推断旧资源已清理。新建合法会话只创建新目录，绝不借用旧目录；未确认资源需要按准确分配身份处置。此限制不同于正常取消/异常的finally清理。

## 无模型开发验证

正式回归通过拦截产品AppServer启动及模拟initialize/execute捕获原argv/cwd/env，再用原生CLI `sandbox --permission-profile ... --cd ...`执行fixture脚本，不启动真实AppServer/Provider/model。覆盖`/tmp`、`/home`的开发/只读，另验证legacy、可选命名配置和模拟proxy relay的配置分支；真实Provider、代理上游或AppServer线程未在该验证中运行。

脚本逐项捕获异常并flush，网络socket失败不丢文件结果；宿主前后核对标记内容、hash和mode。ENOENT单独记为不可见，用宿主存在性和mountinfo证明映射隔离，不伪称EACCES。生命周期测试覆盖成功/失败/取消、复用、身份替换、软链接、启动失败及UNKNOWN恢复不重放。
