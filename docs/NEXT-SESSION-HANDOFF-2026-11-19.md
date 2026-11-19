# 2026-11-19 交接：Gate H V3 通过

> 本文件是公开、脱敏交接。精确 SSH、凭据、密码窗口和完整证据只保存在 Git
> 忽略的 `.codex/`，不得复制到本文件。

## 当前结论

- rc.7 正常运行，Gate G 已通过。
- 单参与者、仅合成内容的 Gate H V3 已通过。
- 本地 loopback tunnel 已关闭，`127.0.0.1:18443` 不再监听。
- 当前系统管理员的唯一 active team membership 已添加并保留。
- 员工范围内更大入口、更多参与者和 Pilot 扩量仍未获批。

## 新会话先读

1. `AGENTS.md`
2. `.codex/PROJECT_GOAL.md`
3. `.codex/STATUS.md`
4. `.codex/PROJECT_PLAN.md`
5. `.codex/handoff.md`
6. `.codex/APPROVALS.md`
7. 本文件

## 固定运行身份

- Application source：
  `c8f683ab9785c6eefc5caa071b135ed1ac227af7`
- Running App：`0.1.0-rc.7`
  `sha256:3e2515b926e607152bcc9126c10f747cec023599e04e025be29cd3fbcd1946cb`
- Rollback App：`0.1.0-rc.6`
  `sha256:ada8b2bc3b876ed1bc64ee3d83d5bb464699bbd6197bc95e88bd8f1105139ea8`
- Database：schema 9，18 张 public 表
- Token 5 expiry：`2026-11-20 18:31:37 Asia/Shanghai`

## Gate H V3 结果

浏览器探针最终结果：

```json
{"ok":true,"stage":"complete","models_verified":true,"nonstream_verified":true,"sse_verified":true,"tool_verified":true,"key_revoked":true,"key_rejected_after_cleanup":true,"secret_value_returned":false,"prompt_values_returned":false,"response_values_returned":false}
```

控制台中出现的 401 是 key 撤销后的预期拒绝测试；探针整体为成功。

数据库 content-free 验证：

- active system-administrator memberships：1；
- 最近临时 Personal Keys：2，均已 revoked；
- complete HTTP-200 success audits：3；
- finish reasons：2 个 `stop`、1 个 `tool_calls`；
- encrypted raw rows：3 request、3 response；
- usage records：3，全部 token totals 有效；
- 没有返回 prompt、response、key 或数据库行值。

## 已完成处置

- 首次自动 scheduler 在启动前失败，没有产生 attempt marker。
- V3 runner 手动启动成功，liveness/readiness/未认证拒绝均通过。
- 测试完成后手动关闭 tunnel 和 stop scheduler。
- Personal API Key 已撤销并验证拒绝访问。
- administrator membership 已按批准保留。

## 关键证据

- V3 probe：
  `.codex/gate_h_v3_probe_result_20261119.json`
- V3 tunnel stop：
  `.codex/gate_h_tunnel_v3_20261119.result.json`
- V3 database verification：
  `.codex/gate_h_v3_database_verification_20261119.json`
- Gate G V8：
  `.codex/gate_g_full_gateway_v8_20261118.result.json`
- rc.7 deployment：
  `.codex/deploy_candidate_rc7_20261118.result.json`

## 不得重放

- Gate H V1 已取消未使用。
- Gate H V2 失败并 consumed。
- Gate H V3 通过并 consumed。
- Gate G V1-V8、rc.5/6/7 deployment、V6 backup、V9 restore 均 consumed。
- 不删除或重写 attempt marker、receipt 或 result。

## 下一阶段

扩量需要新的明确决策：

1. 判断单人 Gate H 证据是否足够；
2. 定义下一批参与者与观察窗口；
3. 定义内部 HTTPS 入口、监控负责人和回滚负责人；
4. 在 Token 5 到期前决定继续使用还是轮换；
5. 创建新的批准、runner/package 和恢复边界。

## 工作区提醒

用户未跟踪的 `prompts/` 和并发 investigation 改动可能仍存在；它们不属于
rc.7 发布内容，必须保留并单独审查，不要擅自回滚或提交。
