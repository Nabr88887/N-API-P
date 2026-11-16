# 2026-11-16 交接：正式部署前剩余工作

## 当前结论

N-API-P rc.5 已完成恢复到可部署前的准备：

- 独立 PostgreSQL `n_api_p` 为干净 schema version 9，18 张 public 表符合 allowlist。
- 已生成并验证排除 `audit_raw_content` 的加密 metadata 恢复点：
  `metadata-20261116T073533Z-4fd2e3`，12,599 bytes，SHA-256
  `855cf5b514afed721226d669dd899acf7f292228596338bf12badb1ed5fa6026`。
- 隔离实际恢复演练通过：16 张 metadata 表恢复、raw 为空、旧凭据/授权失效、
  审计门 blocked、临时数据库删除、源数据库未修改，远端耗时 4.143 秒。
- 合成恢复演练还证明旧 synthetic session/personal/service key 被拒绝，
  replacement synthetic key 可认证，审计门只在持久化探针后恢复。
- rc.5 镜像
  `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`
  已在现有服务器 Docker 中按摘要预置并校验，未启动候选容器。
- 正式部署脚本和自动回滚包已准备，只切换 `app`，不碰 Proxy、PostgreSQL、
  NewAPI、卷、网络或 schema。

## 当前阻塞

正式部署本身等待用户最终确认；模型链路还等待两个运维前置：

1. 现有挂载的 token ID 2 已于 2026-11-14 10:00（Asia/Shanghai）原生过期；
   2026-11-16 的新鲜远端 preflight 在通过其余全部检查后，仅以
   `upstream_auth_rejected` 停止。已准备一次性 token 轮换包：创建限定
   `deepseek-v4-flash`、额度不超过 10 CNY、有效期不超过 96 小时的 token，
   先验证 `/v1/models`，再原子替换 root-owned `0400` carrier；失败会撤销新
   token 并恢复旧载体。执行时只需在本地隐藏提示中输入一次 NewAPI 管理员
   凭据，凭据和 token 不会输出或落盘。
2. 本地 DPAPI 恢复密钥载体已通过回读校验，但仍需复制到运维控制的离线介质：
   `tmp/predeployment-recovery-carrier-20261116/metadata-backup-v1.key.dpapi`
   及同目录 content-free manifest。当前主机只检测到固定的 C/D/E 卷和空
   CD-ROM，没有可移动文件系统，因此仍需人工插入运维控制的离线介质。

在上述两项完成前，不得把 Gate G 标为通过，也不得开放员工入口或试点流量。

## 已完成验证

- Go unit test：通过。
- Go race test：通过。
- Go vet/build/mod verify：通过。
- PostgreSQL integration：通过，100.483 秒。
- 前端：17 files / 122 tests、ESLint、TypeScript、Vite build 通过。
- Playwright desktop/mobile：16/16 通过。
- OpenSpec strict：3/3 通过。
- `npm audit --audit-level=high`：通过；仍有 9 个 moderate，均位于开发期
  lint/test 工具链，自动全修会引入 breaking 更新，未在发布候选上改依赖。
- rc.5 OCI archive：16,618,496 bytes，11/11 blob 通过，index、平台、版本、
  revision、healthcheck、运行用户和 stop signal 均匹配。
- token 轮换包：本机 9/9 通过（跳过 1 个 Linux-only 测试）；
  `python:3.12-slim` 内 9/9 通过，包括目录相对原子替换。
- 部署脚本回归：4/4 通过。

## 固定身份

- Application source：`798b242505123f34e69c0439651776502cd35955`
- Candidate：`0.1.0-rc.5`
- Candidate image：
  `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`
- Current rollback image：
  `sha256:6c5def141120d85f9843f0a9f119c76d196f20a87bfb8c59b00d1902cb36b4d9`
- Candidate archive SHA-256：
  `20370b09696709ca2940b34fff467878edcc3c417d015365ade8124515c6380a`

## 新会话执行顺序

1. 读取 `AGENTS.md`、`.codex/PROJECT_GOAL.md`、`.codex/STATUS.md`、
   `.codex/PROJECT_PLAN.md`、`.codex/handoff.md` 和本文件。
2. 核对 Git、候选镜像、恢复证据和所有 CONSUMED 包，不重放旧包。
3. 先运行 token 轮换包本地 preflight，再在本地隐藏提示中输入 NewAPI 管理员
   凭据并执行一次；核对 receipt 中的 token 元数据、模型发现和 carrier 权限。
4. 插入并核对运维控制的离线介质，复制 DPAPI carrier 与 manifest，再回读哈希。
5. 在服务器只运行：
   `.codex/deploy_candidate_rc5_20261116.py preflight`。
6. 只有 preflight 全部通过并获得用户最终正式部署确认后，才运行 `deploy`。
7. `deploy` 成功后再运行 `verify`，确认 companions 未变化、候选健康、
   DB version 9、代理仍仅回环监听。
8. 使用新 token 做 Gate G：models、非流式 Chat、SSE、tool call、usage、
   加密 raw capture、审计完整性、内容免费日志/metrics。
9. Gate H 的参与者、时间窗和内部入口仍是独立决定。

## 禁止事项

- 不重放任何已消费 runner 或删除 marker/result。
- 不对现有 `n_api_p` 做 live restore、迁移、删除或强制回滚。
- 不使用 down migration、force migration、Docker prune 或卷删除。
- 不读取/输出 NewAPI token、audit key、DB password、员工提示词或响应。
- 不把 9 个 moderate dev-only 依赖告警描述为零风险，也不在未验证情况下
  `npm audit fix --force`。
- 不把 local mock、NewAPI 回环或旧 Pro smoke 当作候选网关 Gate G。

## 详细入口

- 状态：`.codex/STATUS.md`
- 当前计划：`.codex/PROJECT_PLAN.md`
- 最终部署包：`.codex/PREDEPLOYMENT-FINAL-DEPLOYMENT-PACKAGE-2026-11-16.md`
- 部署脚本：`.codex/deploy_candidate_rc5_20261116.py`
- token 轮换计划：`.codex/PREDEPLOYMENT-TOKEN-ROTATION-V1-2026-11-16.md`
- token 轮换 runner：
  `.codex/predeployment_token_rotation_v1_once_20261116.py`
- 新鲜部署 preflight：
  `.codex/predeployment_final_deployment_preflight_v2_20261116.result.json`
- 恢复点计划：`.codex/PREDEPLOYMENT-METADATA-BACKUP-V3-2026-11-16.md`
- 实际恢复演练：`.codex/PREDEPLOYMENT-ACTUAL-RESTORE-DRILL-V6-2026-11-16.md`
- 权威批准与消费状态：`.codex/APPROVALS.md`
