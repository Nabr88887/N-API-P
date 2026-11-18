# 2026-11-18 交接：rc.7 正式部署与 Gate G 完成

> 本文件是公开、脱敏交接。精确 SSH、凭据、密码窗口和完整证据只保存在 Git
> 忽略的 `.codex/`，不得复制到本文件。

## 新会话先读

1. `AGENTS.md`
2. `docs/NEXT-SESSION-HANDOFF-2026-11-16.md`
3. `.codex/PROJECT_GOAL.md`
4. `.codex/STATUS.md`
5. `.codex/PROJECT_PLAN.md`
6. `.codex/handoff.md`
7. `.codex/APPROVALS.md`
8. 本文件

## 当前结论

- rc.7 已正式部署并通过独立 verify。
- Gate G V8 完整通过。
- 员工入口、Pilot 和 Gate H 仍关闭。
- Token ID 5 到期时间为 `2026-11-20 18:31:37 Asia/Shanghai`。

## 固定身份

- Source commit：
  `c8f683ab9785c6eefc5caa071b135ed1ac227af7`
- Running App：`0.1.0-rc.7`
  `sha256:3e2515b926e607152bcc9126c10f747cec023599e04e025be29cd3fbcd1946cb`
- Rollback App：`0.1.0-rc.6`
  `sha256:ada8b2bc3b876ed1bc64ee3d83d5bb464699bbd6197bc95e88bd8f1105139ea8`
- Candidate archive：
  16,619,520 bytes，SHA-256
  `bcd68fa2916f63adef30d7d2de753a825571e263240444f20b4c9a77140cc504`
- Recovery point：`metadata-20261118T150636Z-605733`，18,022 bytes，
  SHA-256
  `24435f898a8bbf0301f7778164c09979330e97c3c5ee5bf254f5aad75b3544d4`
- Database：`n_api_p`，schema 9，18 张 public 表。

## 根因与修复

V5 直接上游 shape probe 证明 Flash non-streaming tool call 合法返回 HTTP 200，
并包含 `choices[].index` 与 `tool_calls[].index`。Gateway 请求解析仍保持严格，
但响应校验复用了仅适用于请求的 `ChatToolCall`，因此拒绝 provider 的
`tool_calls[].index`。

rc.7 新增独立的响应 tool-call decoder：

- 接受可选、非负整数 `index`；
- 继续验证 `id`、`type=function`、function name 与字符串 arguments；
- 继续拒绝其他未知字段；
- 不改写或重新编码上游响应。

RED/GREEN 回归测试位于：

- `backend/internal/gateway/chat_contract_test.go`
- `backend/internal/gateway/chat_proxy.go`

## 验证基线

- Go 全量 tests：PASS。
- Go race：PASS。
- Go vet/build/mod verify：PASS。
- PostgreSQL integration：PASS，95.295 秒。
- Frontend `npm run verify`：17 files / 122 tests、lint、TypeScript、Vite：PASS。
- OpenSpec strict：3/3 PASS。
- npm audit：仍为 8 high + 8 moderate，均位于开发期 Vite/Vitest/
  typescript-eslint 工具链；用户已接受 dev-only high advisory。rc.7
  runtime 为 `scratch`，不含 Node.js、`node_modules` 或包管理器。
- Metadata backup V6：PASS / CONSUMED。
- Actual restore drill V9：PASS，4,217 ms。
- rc.7 remote staging：PASS / CONSUMED。
- rc.7 fresh preflight：PASS。
- rc.7 App-only deploy：PASS。
- rc.7 independent verify：PASS。

## Gate G V8

结果：`gate_g_full_verified`

- Pro non-streaming：PASS。
- Pro SSE：PASS。
- Flash tool call：PASS。
- Complete encrypted audits：3。
- Encrypted raw capture：PASS。
- Usage：PASS。
- Content-free logs/metrics：PASS。
- Post-cleanup synthetic key rejection：PASS。
- Synthetic identity/team/key cleanup：PASS。
- No prompt/response/secret/row values returned。

结果 SHA-256：
`a016ffbf0ef469043af894fce5a9e077be8690d63734af27537682883731e6e5`

attempt SHA-256：
`c51e412f518351bd31b6d285162c2620c6504a4782dbb988493961aee34ea454`

## 关键证据入口

- rc.7 deployment：
  `.codex/deploy_candidate_rc7_20261118.result.json`
- rc.7 staging：
  `.codex/predeployment_candidate_staging_rc7_v1_20261118.result.json`
- metadata backup V6：
  `.codex/predeployment_metadata_backup_v6_20261118.result.json`
- restore drill V9：
  `.codex/predeployment_actual_restore_drill_v9_20261118.result.json`
- Gate G V8：
  `.codex/gate_g_full_gateway_v8_20261118.result.json`
- Direct Flash shape proof V5：
  `.codex/gate_g_flash_shape_probe_v5_20261118.result.json`

## 不得重放

- Gate G V1-V8 全部 consumed。
- Recovery V1-V12、Policy V1/V3、Metadata backup V1-V6、Restore drill V1-V9
  全部 consumed。
- rc.5/rc.6/rc.7 deployment package、rc.6 staging V1/V2、rc.7 staging V1
  全部 consumed。
- 不得删除或重写 attempt marker、receipt 或 result。

## 工作区提醒

rc.7 绑定源码 commit `c8f683a`。部署完成后，工作区出现了与本发布任务无关的
investigation 功能改动；这些改动未被 rc.7 使用，必须保留并由后续任务单独审查。
不要把它们包装成 rc.7，也不要擅自回滚。

## Gate H 当前状态

用户已于 2026-11-19 确认最小首轮范围，批准记录为
`GATE-H-PILOT-RC7-V1-20261119`，当前状态为 `APPROVED / UNUSED`：

- 参与者：仅请求用户本人；
- 窗口：`2026-11-19 10:00-12:00 Asia/Shanghai`；
- 入口：仅本机 SSH 转发到 `127.0.0.1:18443`；
- 数据：仅合成提示词和响应；
- 监控和回滚负责人：请求用户本人；
- 运行镜像：rc.7，回滚镜像：rc.6。

2026-11-19 00:00 的只读 preflight 已通过，当前本地 `18443` 没有监听，隧道未提前
建立。执行入口：

```powershell
.\.venv\Scripts\python.exe -B .codex\gate_h_tunnel_20261119.py --preflight
.\.venv\Scripts\python.exe -B .codex\gate_h_tunnel_20261119.py --start
.\.venv\Scripts\python.exe -B .codex\gate_h_tunnel_20261119.py --status
.\.venv\Scripts\python.exe -B .codex\gate_h_tunnel_20261119.py --stop
```

`--start` 只允许在 `09:55-10:10` 运行；必须在 `12:00` 前或任一回滚条件出现时
立即 `--stop`。不得直接把 `18443` 发布到公网接口，不得扩大参与者或使用真实
员工内容。

## 禁止事项

- 不开放员工入口或 Pilot，除非获得新的 Gate H 明确批准。
- 不操作 NewAPI 数据库或修改其账号/邮箱。
- 不输出 token、密码、DSN、audit key、员工提示词或响应。
- 不做 live restore、down/force migration、volume 删除或通用 Docker prune。
- 不提交 `.codex`、`prompts/`、本地私密交接或无关工作区改动。
