# 2026-11-16 交接：正式部署前剩余工作

> 2026-11-18 更新：本文件保留为历史交接。当前有效状态请以
> [`NEXT-SESSION-HANDOFF-2026-11-18.md`](NEXT-SESSION-HANDOFF-2026-11-18.md)
> 和 `.codex/handoff.md` 为准。下方部署脚本哈希的旧记录少了一个十六进制
> 字符，已按实际文件修正。

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

## 当前状态与阻塞

App-only 部署所需的远端只读 preflight 已于 2026-11-16 新鲜通过，退出码 0，
返回 `preflight_passed`。上游 token 问题已闭环：

- 旧 token ID 2 已过期。
- 轮换过程中创建后又撤销了 token ID 3、4，未留下运行凭据。
- 当前有效 token ID 5 为 owner-bound `deepseek-v4-pro`，额度
  9.9999926 CNY，原生到期时间 2026-11-20 18:31:37（Asia/Shanghai）。
- token ID 5 已写到运行 App 实际挂载的
  `/srv/n-api-p/secrets/newapi-token`，root-owned `0400`。
- 代理仅允许 App IP `172.31.0.3`；部署 preflight 已改为进入 App network
  namespace 验证 `/v1/models`，不再从宿主机错误来源探测。

正式部署仍等待：

1. 本地 DPAPI 恢复密钥载体已通过回读校验，但仍需复制到运维控制的离线介质：
   `tmp/predeployment-recovery-carrier-20261116/metadata-backup-v1.key.dpapi`
   及同目录 content-free manifest。当前主机只检测到固定的 C/D/E 卷和空
   CD-ROM，没有可移动文件系统，因此仍需人工插入运维控制的离线介质。
2. 用户对最终 App-only 切换作出明确部署确认。

在上述两项完成前，不执行正式切换，也不开放员工入口或试点流量。

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
- token 基础轮换包：本机 9/9 通过（跳过 1 个 Linux-only 测试）；
  `python:3.12-slim` 内 9/9 通过，包括目录相对原子替换。
- active-binding v4：本机和 Linux 容器均 5/5 通过。
- 部署脚本回归：4/4 通过。
- App-only 部署 preflight：新鲜的 `preflight_passed`，退出码 0。

## 固定身份

- Application source：`798b242505123f34e69c0439651776502cd35955`
- Candidate：`0.1.0-rc.5`
- Candidate image：
  `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`
- Current rollback image：
  `sha256:6c5def141120d85f9843f0a9f119c76d196f20a87bfb8c59b00d1902cb36b4d9`
- Active upstream token：ID 5 / `deepseek-v4-pro`，到期
  `2026-11-20 18:31:37`（Asia/Shanghai）
- Active carrier：`/srv/n-api-p/secrets/newapi-token`，root `0400`
- Candidate archive SHA-256：
  `20370b09696709ca2940b34fff467878edcc3c417d015365ade8124515c6380a`

## 新会话执行顺序

1. 读取 `AGENTS.md`、`.codex/PROJECT_GOAL.md`、`.codex/STATUS.md`、
   `.codex/PROJECT_PLAN.md`、`.codex/handoff.md` 和本文件。
2. 核对 Git、候选镜像、恢复证据和所有 CONSUMED 包，不重放旧包。
3. 插入并核对运维控制的离线介质，复制 DPAPI carrier 与 manifest，再回读哈希。
4. 获得用户对最终 App-only 切换的明确确认。
5. 在服务器运行：
   `.codex/deploy_candidate_rc5_20261116.py deploy`。
6. `deploy` 成功后再运行 `verify`，确认 companions 未变化、候选健康、
   DB version 9、代理仍仅回环监听。
7. 使用 token ID 5 做 Gate G：models、非流式 Chat、SSE、tool call、usage、
   加密 raw capture、审计完整性、内容免费日志/metrics。
8. Gate H 的参与者、时间窗和内部入口仍是独立决定。

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
- 部署脚本 SHA-256：
  `453fae6cef51446efe0c3bc6c3fa2c7257309cb938dc10f11ab096f5cbae33c5`
- token 绑定修正计划：`.codex/PREDEPLOYMENT-TOKEN-ROTATION-V4-2026-11-16.md`
- token 绑定修正 runner：
  `.codex/predeployment_token_rotation_v4_once_20261116.py`
- 新鲜部署 preflight：
  `.codex/predeployment_final_deployment_preflight_v2_20261116.result.json`
- 恢复点计划：`.codex/PREDEPLOYMENT-METADATA-BACKUP-V3-2026-11-16.md`
- 实际恢复演练：`.codex/PREDEPLOYMENT-ACTUAL-RESTORE-DRILL-V6-2026-11-16.md`
- 权威批准与消费状态：`.codex/APPROVALS.md`
