# 2026-11-18 交接：rc.6 最终部署与 Gate G V6

> 本文件是公开、脱敏交接。精确管理员邮箱、本地 SSH 配置和密码窗口信息只保存在
> Git 忽略的 `.codex/`，不得复制到本文件或远端。

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

取得 rc.6 最终部署决定，部署 rc.6 App-only，随后新建 Gate G V6 并完成
Pro/Flash 全链路验收。

## 当前状态

- rc.5 仍是运行中版本，服务和 Compose 未变化。
- N-API-P 唯一系统管理员已恢复；旧会话撤销、API Key 保持、安全事件已落库。
- Pro + Flash 已正式应用并回读：
  - App allowlist 保留 Pro，并添加 allowed Flash；
  - NewAPI channel 1 与 Token 5 均为
    `deepseek-v4-pro,deepseek-flash`。
- Gate G V4/V5 均 FAILED/CONSUMED，不得重放。
- V5 证明 rc.5 在转发前拒绝 provider `thinking` 字段。源码已增加严格可选的
  `thinking: {"type":"enabled"|"disabled"}` 契约，并保持原请求体转发与审计。
- 全量 Go、race、vet/build/mod verify、PostgreSQL integration、前端 122
  tests/lint/build、OpenSpec strict 均通过。
- rc.6 镜像已构建、归档、远端预置并通过只读 preflight：
  `sha256:ada8b2bc3b876ed1bc64ee3d83d5bb464699bbd6197bc95e88bd8f1105139ea8`。
- 新恢复点 `metadata-20261118T073633Z-6ebbe8` 已创建，V8 可丢弃数据库恢复演练
  4,172 ms 通过。

## 唯一剩余部署决定

当前 npm advisory 数据库显示开发期 Vite/Vitest/typescript-eslint 工具链有 8 个
high；相关 `picomatch` 范围暂无已发布修补版本。最终 runtime 镜像是 `scratch`，
只有四个 Go 二进制和 CA bundle，不含 Node.js、`node_modules` 或包管理器。

正式部署前必须明确选择：

1. 接受这个仅开发期/构建期的残留风险；或
2. 先批准 dev dependency 修正，然后重建、重新完整验证、刷新恢复点并重新预检。

没有该决定，不得部署。

## 明天的固定顺序

### 1. rc.6 App-only 部署

用户批准后：

1. 把 `.codex/APPROVALS.md` 中
   `FINAL-APP-RC6-DEPLOYMENT-V1-20261118` 从 pending 改为 approved；
2. 不改任何 hash 或 scope；
3. 运行：

   ```powershell
   .\.venv\Scripts\python.exe -B .codex\deploy_candidate_rc6_once_20261118.py --preflight
   .\.venv\Scripts\python.exe -B .codex\deploy_candidate_rc6_once_20261118.py --confirm-rc6-deployment
   ```

预期结果：`rc6_deploy_and_verify_passed`。失败时远端自动恢复 rc.5；attempt
marker 已消费后不得重放。

### 2. Gate G V6

不得重放 V5。新建 V6，保持：

- Pro 用于 non-streaming 和 SSE；
- Flash 用于 tool case；
- `tool_choice: auto`；
- `thinking: {"type":"disabled"}`。

要求 models 包含 Pro/Flash，非流式、SSE、Flash tool、usage、三条完整加密
audit、content-free logs/metrics、合成 key 清理全部通过。最多一次 SSH 和三次
provider inference。

### 3. Gate H

只在 Gate G 完整通过后单独评估。员工入口和 Pilot 仍关闭。

## 固定身份

- Parent repository HEAD：
  `5adb23c6e01091621a19d707956a51012f6ad119`
- Reviewed rc.6 source snapshot：
  `f26b5677c89cd24c8df6ca9e31e1bb40c0b3fd35`
- Running / rollback：
  `0.1.0-rc.5`,
  `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`
- Staged candidate：
  `0.1.0-rc.6`,
  `sha256:ada8b2bc3b876ed1bc64ee3d83d5bb464699bbd6197bc95e88bd8f1105139ea8`
- Candidate archive：
  16,618,496 bytes,
  SHA-256
  `922ff972f1e847fc921d9258b0caed2e35efc2658aa34e28a84eea2c17328a37`
- Recovery point：
  `metadata-20261118T073633Z-6ebbe8`, 16,330 bytes,
  SHA-256
  `8ef6ab04b1abfd2eabd7402f7ad5a316a1bf3ebc6045b8f3f96fb0577fd669a9`
- Token 5 到期：`2026-11-20 18:31:37 Asia/Shanghai`

## 关键证据

- rc.6 staging：
  `.codex/predeployment_candidate_staging_rc6_v2_20261118.result.json`
- rc.6 deployment preflight：
  `.codex/RC6-FINAL-PREFLIGHT-20261118.result.json`
- deployment builder：
  `.codex/deploy_candidate_rc6_20261118.py`
- deployment runner：
  `.codex/deploy_candidate_rc6_once_20261118.py`
- fresh backup：
  `.codex/predeployment_metadata_backup_v5_20261118.result.json`
- fresh restore drill：
  `.codex/predeployment_actual_restore_drill_v8_20261118.result.json`
- Gate G V5 consumed：
  `.codex/gate_g_full_gateway_v5_20261118.result.json`
- Pro+Flash policy V3：
  `.codex/newapi_pro_flash_policy_v3_20261118.result.json`
- Admin recovery V12：
  `.codex/n_api_p_operator_password_recovery_v12_20261118.result.json`

## 禁止事项

- 不重放任何 consumed recovery、policy、Gate G、backup、restore 或 staging 包。
- 不直接改 N-API-P 数据库 policy。
- 不操作 NewAPI 数据库或账号邮箱。
- 不开放员工入口、Pilot 或 Gate H。
- 不输出密码、token、DB password、DSN、员工提示词或响应。
- 不提交 `.codex`、本地私密交接、`prompts/` 或无关改动。
