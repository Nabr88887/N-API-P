# 2026-11-18 交接：先恢复 N-API-P 管理员，再完成 Pro+Flash

> 本文件是明天新会话的公开、脱敏交接。精确管理员邮箱和本地 SSH 配置只保存在
> Git 忽略的 `.codex/handoff.md`，不得复制到本文件或公开远端。

## 新会话先读

1. `AGENTS.md`
2. `.codex/PROJECT_GOAL.md`
3. `.codex/STATUS.md`
4. `.codex/PROJECT_PLAN.md`
5. `.codex/handoff.md`
6. `.codex/APPROVALS.md`
7. `.codex/DECISIONS.md`
8. 本文件

## 一句话目标

先以不依赖门户 HTTP 的一次性事务恢复唯一 N-API-P 系统管理员，再应用用户已确认
的 Pro+Flash 政策，最后重跑完整 Gate G。

## 最容易混淆的账号边界

- **NewAPI**：管理员用户名 + 密码；没有绑定邮箱。
- **N-API-P 门户**：`identities.email` + 密码。
- 明天不得再为 NewAPI 询问或修改邮箱。
- 精确 N-API-P 管理员邮箱在 `.codex/handoff.md`，仅本地使用。

## 当前固定基线

- 工作区：`E:\new_projiect\N-API-P`
- Git HEAD（本次文档提交前）：
  `6b74721f07f0420ebbcc6e93efa02f56a6c1fb6a`
- Application source/revision：
  `798b242505123f34e69c0439651776502cd35955`
- 运行中 App：
  `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`
- Rollback image：
  `sha256:6c5def141120d85f9843f0a9f119c76d196f20a87bfb8c59b00d1902cb36b4d9`
- NewAPI Token 5：`deepseek-v4-pro`，到
  `2026-11-20 18:31:37 Asia/Shanghai`。
- App、NewAPI 仍仅回环绑定；员工入口和 Pilot 关闭。

## 今天已完成

- rc.5 App-only 部署成功并通过独立验证。
- Gate G 部分通过：models、普通 Chat、SSE、usage、加密 raw、审计、
  content-free logs/metrics 通过。
- `deepseek-v4-pro` 的 tool call 仍返回上游 HTTP 400。
- 隔离 Flash probe 返回 HTTP 200、`finish_reason=tool_calls`；临时 token
  已撤销、channel 已恢复、Token 5 未变。
- 用户明确选择 **Pro + Flash**。
- Pro+Flash 正式策略尚未应用，因为唯一的 N-API-P 系统管理员密码无法登录。

## 管理员恢复失败链

- 正常登录检查返回 `portal_credential_invalid`。
- v1-v10 恢复包全部 FAILED/CONSUMED，不得重放。
- 所有到达数据库修改阶段的包都完成了回滚和清理：
  `rollback_verified=true`、`cleanup_verified=true`。
- 未留下密码哈希、门户会话、API Key 或安全事件的净变更。
- 最后失败点是门户 HTTP 代理传输，不是 Argon2id 密码写入本身。
- App 网络内只读诊断对推断的代理 `IP:18443` 返回
  `ConnectionRefusedError`。

## 明天的实现决定

不要再做 HTTP 耦合的 v12/v13 盲试。新建一个单用途恢复包：

1. 只读确认唯一 active `system_administrator` 和精确邮箱。
2. 在 serializable transaction 内锁定该行。
3. 用项目 `internal/access` 生成 Argon2id hash，并在内存中验证新密码。
4. 只更新 password hash、失败登录/锁定字段和 `updated_at`。
5. 撤销该身份的旧门户会话。
6. 插入一条 content-free `password_reset_completed` 安全事件。
7. 在同一事务提交前重新读取 hash，再用项目 Argon2id 验证新密码。
8. 保留 API Keys、角色、状态和其他所有数据。
9. 事务成功后才返回安全 receipt。
10. 用户另行手动登录门户确认，不再把门户 HTTP 作为事务提交条件。

## 管理员恢复后的顺序

1. 用户手动登录确认 N-API-P 系统管理员可用。
2. 通过审计化管理员 API 应用 Pro+Flash：
   - App allowlist 保留 Pro，添加 allowed Flash；
   - NewAPI channel 1：
     `deepseek-v4-pro,deepseek-flash`；
   - Token 5 model scope：
     `deepseek-v4-pro,deepseek-flash`；
   - 其他字段保持不变；
   - 任一步失败自动回滚三项策略。
3. 重跑完整 Gate G；tool case 使用 `deepseek-flash`。
4. Gate G 成功后再单独评估 Gate H。

## 可复用与保留文件

- 状态：`.codex/STATUS.md`
- 计划：`.codex/PROJECT_PLAN.md`
- 决策：`.codex/DECISIONS.md`
- 批准链：`.codex/APPROVALS.md`
- 本地精确交接：`.codex/handoff.md`
- 密码恢复源码：
  `.codex/operator-password-recovery-src-20261117/password_recovery/`
- 最终恢复二进制：
  `.codex/artifacts/n-api-p-password-recovery-v10-20261117.bin`
- Gate G partial：
  `.codex/GATE-G-FULL-20261117.result.json`
- Flash 隔离通过：
  `.codex/newapi_flash_isolated_tool_probe_v3_20261117.result.json`
- 错误档案：
  `D:\Worng-test\records\2026-11-17-n-api-p-account-prompt-confusion.md`

## 禁止事项

- 不重放任何 FAILED/PASSED CONSUMED 包。
- 不为 NewAPI 修改邮箱或创建邮箱绑定。
- 不直接修改 N-API-P `password_hash` 的无审核 SQL。
- 不开放员工入口、Pilot 或 Gate H。
- 不输出密码、token、DB password、DSN、员工提示词或响应。
- 不提交 `.codex`、本地私密交接、`prompts/` 或无关工作区改动。

## 收尾状态

- 今天打开的 SSH tunnel、NewAPI 本地转发和密码窗口均已关闭。
- 密码恢复的临时 Go 源码与最终二进制已从易清理的 `backend/tmp`/`tmp`
  移入 `.codex` 证据目录。
- 明天新会话读取 `.codex/handoff.md` 后，应直接从“无 HTTP 耦合的 v11
  恢复包”开始，不再重新调查账号体系。
