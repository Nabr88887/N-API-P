# 2026-11-17 交接：N-API-P 正式部署前最新状态

> 2026-11-17 晚更新：本文件已转为历史快照。新会话请以
> [`NEXT-SESSION-HANDOFF-2026-11-18.md`](NEXT-SESSION-HANDOFF-2026-11-18.md)
> 和 `.codex/handoff.md` 为准。

## 先读

1. `AGENTS.md`
2. `.codex/PROJECT_GOAL.md`
3. `.codex/STATUS.md`
4. `.codex/PROJECT_PLAN.md`
5. `.codex/handoff.md`
6. `.codex/APPROVALS.md`
7. `.codex/PREDEPLOYMENT-FINAL-DEPLOYMENT-PACKAGE-2026-11-16.md`

## 当前结论

App-only 部署已经完成并通过独立验证。当前状态：

1. 运行 App 为候选 rc.5。
2. 员工入口和试点流量仍关闭。
3. Gate G 为部分通过：models、非流式、SSE、usage、加密审计、
   logs 和 metrics 通过；tool call 被上游拒绝。
4. 隔离 Flash 探测已通过：临时 15 分钟、10,000 raw quota、仅
   `deepseek-flash` 的 token 完成一次 HTTP 200 tool call 后立即撤销；
   channel 1 已恢复为仅 `deepseek-v4-pro`，Token 5 稳定字段未变。
   当前 App allowlist、channel 和 Token 5 仍为 Pro-only。

2026-11-17 已完成的新鲜检查：

- Git 仍为 `main` / HEAD
  `6b74721f07f0420ebbcc6e93efa02f56a6c1fb6a`；应用源码仍为
  `798b242505123f34e69c0439651776502cd35955`。
- 旧运行镜像仍为
  `sha256:6c5def141120d85f9843f0a9f119c76d196f20a87bfb8c59b00d1902cb36b4d9`，
  健康、零重启。
- 候选仍为
  `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`。
- NewAPI token 载体仍为 root `0400` 普通文件、48 bytes；App-network
  `/v1/models` 探测通过。
- 新的 metadata recovery point
  `metadata-20261117T065147Z-98e4a8` 已创建，12,598 bytes，SHA-256
  `78dc6a7592bba1becbe8633b575aa96bad3b41aa9eb59f064e888caadc8fb7b7`。
- 新恢复点已用 disposable DB v7 实际恢复：migration 9、16 表、raw 空、
  凭据/授权失效、审计门 blocked、临时库删除、源库未修改，4,777 ms。
- 部署脚本已绑定新恢复点，测试 4/4；新鲜远端 preflight 返回
  `preflight_passed`、exit 0。
- DPAPI carrier 已复制到 `F:` Kingston FAT32 离线介质，两个文件回读
  大小与 SHA-256 完全一致并设为只读；介质随后已弹出并显示 No Media。
- 正式 App-only deploy 返回 `deployment_passed`；独立 verify 返回
  `verified`。companions 未变、DB schema 9、入口仍仅回环。
- Flash 隔离探测证据：
  `.codex/newapi_flash_isolated_tool_probe_v3_20261117.result.json`，
  result SHA-256
  `852973afecb45e4b363205bfdf308179f2669a380fc68638c231f1484997960c`；
  attempt SHA-256
  `dc95ba627fc1b99accd26b8880490c1b2ed5aeba343f866c5beb4985997a8e0c`。

## 固定部署身份

- Deployment script: `.codex/deploy_candidate_rc5_20261116.py`
- Deployment script SHA-256:
  `453fae6cef51446efe0c3bc6c3fa2c7257309cb938dc10f11ab096f5cbae33c5`
- Deployment-script tests: 4/4 PASS
- Latest preflight result:
  `.codex/predeployment_final_deployment_preflight_v5_20261117.result.json`
- Candidate source/revision:
  `798b242505123f34e69c0439651776502cd35955`
- Candidate version: `0.1.0-rc.5`
- Rollback image:
  `sha256:6c5def141120d85f9843f0a9f119c76d196f20a87bfb8c59b00d1902cb36b4d9`
- Active token: ID 5, `deepseek-v4-pro`, expiry
  `2026-11-20 18:31:37 Asia/Shanghai`

## 下一步

1. 通过审计化的 N-API-P 系统管理员接口调整生产模型 allowlist，并将
   channel 1/Token 5 的模型范围切换到 Flash 或 Pro+Flash；不得绕过审计
   直接改 N-API-P 数据库。
2. 使用切换后的正式政策重新运行完整 Gate G；隔离 provider probe 不能
   代替网关验收。
3. Gate H 的参与人、时间窗和入口仍是独立决定。

## 禁止事项

- 不重放 v1-v4 token 包、metadata backup v4 或 restore drill v7。
- 删除或改写任何 consumed marker/result。
- 读取或输出 NewAPI token、DB password、audit key、员工提示词或响应。
- 直接操作 NewAPI 数据库。
- 对 `n_api_p` 做 live restore、down/force migration、删除或强制回滚。
- 使用 Docker prune、卷删除或扩大入口。
- 把本文件或 `.codex` 本地部署记录发布到公开 Git remote。
