# 2026-11-19 暂停交接：Gate H 已批准但未启动

> 本文件是公开、脱敏交接。精确 SSH、凭据、密码窗口和完整证据只保存在 Git
> 忽略的 `.codex/`，不得复制到本文件。

## 当前结论

- 2026-11-19 00:05 Asia/Shanghai，用户因急事要求暂停。
- rc.7 继续正常运行，Gate G 已完成。
- Gate H 的 2026-11-19 单参与者、仅循环隧道、仅合成数据窗口已批准，但在启动
  前被取消，**没有建立隧道，没有 Pilot 流量**。
- 本地 `18443` 已确认关闭，没有 Gate H attempt/state/result 文件。
- 员工入口、Pilot 和 Gate H 对外状态仍为关闭。

## 新会话先读

1. `AGENTS.md`
2. `docs/NEXT-SESSION-HANDOFF-2026-11-16.md`
3. `.codex/PROJECT_GOAL.md`
4. `.codex/STATUS.md`
5. `.codex/PROJECT_PLAN.md`
6. `.codex/handoff.md`
7. `.codex/APPROVALS.md`
8. 本文件

## 固定运行身份

- Running App：`0.1.0-rc.7`
  `sha256:3e2515b926e607152bcc9126c10f747cec023599e04e025be29cd3fbcd1946cb`
- Source commit：`c8f683ab9785c6eefc5caa071b135ed1ac227af7`
- Rollback App：`0.1.0-rc.6`
  `sha256:ada8b2bc3b876ed1bc64ee3d83d5bb464699bbd6197bc95e88bd8f1105139ea8`
- Database：`n_api_p`，schema 9，18 张 public 表
- Current ingress：server proxy 仅监听 `127.0.0.1:18443`
- Current local tunnel：未运行
- Token 5 expiry：`2026-11-20 18:31:37 Asia/Shanghai`

## 今天完成的事项

- rc.7 已正式部署并通过独立 verify。
- Gate G V8 完整通过：Pro 非流式、Pro SSE、Flash tool、usage、3 条加密审计、
  content-free logs/metrics、清理和 key rejection。
- 新增 rc.7 Gate H 决策包：
  `deploy/GATE-H-PILOT-DECISION-RC7-2026-11-18.md`
- 用户确认最小首轮范围后，新增批准
  `GATE-H-PILOT-RC7-V1-20261119` 和本地 tunnel runner：
  `.codex/gate_h_tunnel_20261119.py`。
- tunnel runner 4/4 tests 通过；只读 preflight 通过；未提前启动。
- 用户暂停后，该批准已封存为
  **CANCELLED / UNUSED / NOT STARTED**，不得明天复用。

## 明天第一工作包

1. 核对 Git、worktree 所有权、rc.7 运行摘要、health、schema 9、
   companions 和 loopback ingress。
2. 核对本地 `18443` 仍关闭，且不存在 Gate H attempt/state/result。
3. 核对 Token 5 剩余有效期。**Token 5 将在 2026-11-20 18:31:37 到期。**
4. 在以下两种路径中先作明确选择：
   - 新的短 Gate H 窗口，必须在 Token 5 到期前留出足够收尾和回滚余量；
   - 或先走独立的 Token 5 轮换批准，再进行 Gate H。
5. 新 gate H 必须使用新的日期、窗口、批准 ID 和 runner hash；不能修改或复用
   2026-11-19 的取消批准。
6. 保持首轮最小范围：1 名指定参与者、仅合成内容、最多 2 小时、
   SSH loopback tunnel、无公网 listener。

## 下一阶段规划

### H0 - 新窗口 readiness

- 只读检查 rc.7、DB schema、恢复点年龄、Token 有效期和本地端口状态。
- 确认 rc.6 回滚镜像仍存在。
- 明确参与者、时间窗、监控负责人和回滚负责人。

### H1 - 单参与者 Pilot

- 只在获批时间窗启动本机 SSH 隧道。
- 参与者仅使用现有门户和合成内容。
- 监控错误率、延迟、审计完整性、usage、readiness、资源使用和日志安全。
- 任一红线立即关闭隧道；应用故障时才考虑 rc.6 回滚。

### H2 - 收尾

- 关闭隧道并确认 `18443` 不再监听。
- 撤销不再需要的 pilot Personal API Key。
- 保留合成 usage/audit metadata 和 content-free 结果。
- 记录 `go`、`hold` 或 `rollback`。
- 任何扩人员、扩时间或真实数据都需要新批准。

## 关键证据

- 部署结果：`.codex/deploy_candidate_rc7_20261118.result.json`
- Gate G V8：`.codex/gate_g_full_gateway_v8_20261118.result.json`
- Gate H readiness：
  `.codex/gate_h_readiness_preflight_20261118.result.json`
- 已取消的 Gate H runner：
  `.codex/gate_h_tunnel_20261119.py`
- 决策包：
  `deploy/GATE-H-PILOT-DECISION-RC7-2026-11-18.md`

## 不得重放/不得沿用

- `GATE-H-PILOT-RC7-V1-20261119` 已取消，不得直接运行 `--start`。
- Gate G V1-V8、rc.5/6/7 deployment、V6 backup、V9 restore 均已 consumed。
- 不删除或重写 attempt marker、receipt 或 result。

## 工作区提醒

tracked worktree 中存在与本发布任务无关的 investigation 功能改动；rc.7 镜像
绑定 source `c8f683a`，不能把后续未审查 worktree 改动包装成 rc.7。新会话必须
保留这些改动，单独审查，不擅自回滚。

## 禁止事项

- 未取得新窗口批准前，不建立隧道、不开放员工入口、不启动 Pilot。
- 不把 `18443` 发布到公网接口。
- 不操作 NewAPI 数据库或修改账号/邮箱。
- 不输出 token、密码、DSN、audit key、员工提示词或响应。
- 不做 live restore、down/force migration、volume 删除或通用 Docker prune。
