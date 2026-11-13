# 2026-11-13 收工交接：11-14 优先解决 W3 数据库绑定

用户明确要求今天到此为止，明天新会话继续，并要求优先解决恢复准备与元数据检查阻塞。本文件记录截至收工的事实、边界和可直接执行的下一步；不新增任何远端或数据库权限。正式部署、入口开放、试点流量、备份和恢复仍为 **HOLD**。

## 新会话读取顺序

1. `AGENTS.md`、`.codex/PROJECT_GOAL.md`。
2. `.codex/STATUS.md`、`.codex/handoff.md`。
3. `.codex/APPROVALS.md`：确认本日 W3 包的 FAILED / CONSUMED 状态，不重放。
4. `.codex/PROJECT_PLAN.md`、`.codex/PREDEPLOYMENT-RECOVERY-PREPARATION-2026-11-12.md`。
5. 本文件、`docs/NEXT-SESSION-HANDOFF-2026-11-12.md`、`.codex/ARTIFACT-INDEX-2026-11-12.md`、`docs/PILOT-AND-ROLLBACK-CHECKLIST.zh-CN.md`。
6. 核对 `git rev-parse HEAD`、分支和工作区；最新收工 HEAD 以 `.codex/STATUS.md` 为准。

## 固定配置与不变要求

- 架构沿用 Go 单体、React/TypeScript/Vite 内嵌静态资源、独立 PostgreSQL 和内部 Linux/Docker；不引入新数据库、缓存、队列、对象存储或 IdP。
- 当前候选仍为 rc.5，源码 revision `798b242505123f34e69c0439651776502cd35955`，OCI index `sha256:9f8ef3ac67fe3188597fb4e6b77653677e6fdd8582f8f52c7638924484cb23b5`。本日提交只增加运维交接文档，不改变应用构建输入。
- 唯一模型为用户选定的 `deepseek-v4-pro`；NewAPI 为 stock rc.40，revision `0aec08fee811ec6136828fda790551b49e410301`。不重问模型、不重放 Pro 调用、不补额、不续期。
- 专用 token 原始总额度 684931 raw units，签发时约 9.9999926 CNY（上限 10 CNY）；实际余额和费用未知。固定到期为 2026-11-14 10:00 Asia/Shanghai（epoch `1794621600`）；明天使用前先核对当前时间与有效期，不自动延长。
- 上游路径要求 gateway 到内部 proxy 使用证书校验 HTTPS；proxy 到 NewAPI 的 HTTP 只限已核验私有且未发布的 bridge。此前 Pro 回环 smoke 不证明完整 gateway HTTPS/SSE/tools/审计验收。
- 用户已明确恢复清单“尚未准备”；不得再次索要路径、伪造 verified manifest，或假设现有数据库为空/source version 0。不得在现有服务库做恢复演练，不删卷、不用 down/force migration/live restore。
- 用户授权继续推进到部署准备，但未覆盖的真实凭据、数据库/服务写入、真实数据和正式部署仍须准确批准；正式部署前需最终明确确认。今天没有新增 NewAPI 调用、备份、恢复、服务或部署操作。

## 11-13 W3 结果

- PostgreSQL 固定容器为 `n-api-p-postgres-postgres-1`。独立容器分组诊断 v2 **PASSED / CONSUMED**；容器处于运行状态，挂载和网络固定阶段通过。它未查询数据库，不能作为 schema 或恢复证据。
- 原 recovery binding v1 在 `database_container/container_inspection_failed` 停止；binding v2 结果为 `receipt_invalid`；binding v3 在 `database_catalog/psql_failed` 停止。上述包都已消费，不能重跑。
- psql diag v4 确认 `psql_available:true`，默认 `postgres` Unix-socket 查询以 `psql_connect_failed` 停止；v5 返回 `psql_error_unclassified`；v6 返回 `stage:postgres_connection / class:role_missing`。v4-v6 均 **FAILED / CONSUMED**，raw stderr 均按设计丢弃，不可恢复，不得重放。
- v6 固定 payload SHA-256 `529c61f48ec3c87b356522cdc8e22219113f744cb9ad8c2ec33264ca1ccbebc6`，runner SHA-256 `cbf1a060df50bdbc595328ae909d2166082291928dafb6a92368872e9185ab6c`，结果 SHA-256 `a8930aea70e45e9265c0697b287a5d0b165bae9597f708440eb4e36f795de0f5`，marker SHA-256 `bef601978520ae693b2496e7b71849af8ef3c5a91a5ef892878d7a138c977842`。最终本地测试 5/5、preflight `approval_present:true / remote_invoked:false`；唯一 SSH 返回 role_missing。无数据库事实被接受，无行值、秘密或服务写入。
- 当前准确 gateway DB 名、DB role、迁移版本、表/列 inventory、数据来源、备份目的地、加密 wrapper/key version 和隔离恢复目标仍未知；无真实备份或 manifest。正式部署继续 HOLD。

## 明天第一工作包

1. 复核 Git clean baseline 和所有 v1-v6 receipts/markers 的 hash；不要调用任何已消费 runner。比较 rc.5 应用输入与 11-12 已验证基线，未变化则复用已有本地验证，不重装依赖。
2. 从现有 binding v3 固定查询集准备一个全新的 W3 recovery-binding 包。唯一拟新增的认证输入是固定 PostgreSQL 容器内的 `POSTGRES_USER` 环境变量值，用于以对应角色连接；不读取或使用 `POSTGRES_PASSWORD`、应用 DSN、其他环境变量、配置文件或密钥，不输出/持久化该角色值。继续只返回有界数据库名、public 表名、迁移版本、raw 列名、allowlist `EXISTS` 布尔值、工具可用性及既有示例目录 metadata；不返回行值或行数，不写库/服务。
3. 该包当前尚未创建、测试、pin 或批准。需按新基线做测试、编译、固定所有 source/transport/consumed evidence hash 和 `remote_invoked:false` preflight，再向用户呈现该准确 payload/runner 的一次性批准请求。若 POSTGRES_USER 缺失、连接失败、目标不唯一、schema dirty/unexpected、输出异常或超时，首错停止且不重试。不要读取其它 env 或转储 `Config.Env` 来“排障”。
4. 元数据事实取得后，单独核实数据来源/真实或合成数据边界；随后绑定已审阅的认证加密 wrapper/key version、准确目的地和可丢弃隔离目标。只有取得匹配的明确批准后，才能制作排除 `public.audit_raw_content` 的真实加密逻辑备份和 manifest，并在获批隔离目标演练。不得把本地测试或旧审批当作这些操作的授权。
5. 真实恢复证据和隔离演练通过后，才汇总 Gate D-G 的 exact target、条件式迁移、candidate/rollback、加固/挂载、封闭入口和有界合成全链路验收包。Gate H 试点名单/窗口/入口不自动开放。

## 完成门槛与停止条件

- 阶段完成必须有准确 DB/schema/data 边界、真实 <=24h 加密且验证过的 content-free metadata recovery point、有效 manifest、隔离恢复证据（raw 内容为空、旧 session/key/code/grant 失效、审计门和持久化探针正确、RTO <= 两工作小时），以及可审阅的精确部署/回滚包。
- 仅有说明文档、容器健康或成功的只读 `SELECT 1` 都不构成恢复准备完成。未知目标/来源、非预期 schema、环境/凭据边界扩大、需要写现有库或服务时立即停止并请求准确的新范围。
- 不提交 `.codex/`、`tmp/`、本机连接记录、密钥、一次性 payload/runner/result/marker 或其他 ignored 证据。只读状态与已消费证据保留本地原样。

## 提交与继续

本日收工 commit 仅包含本交接文档及运维手册中的交接入口链接；不 push。`.codex/STATUS.md`、`.codex/handoff.md` 与 `.codex/APPROVALS.md` 保持本地排除，但记录完整最新状态。新会话可直接开始第一个工作包，不必重新调查历史 W3 失败。

明天可直接对新会话说：

> 请先按 `docs/NEXT-SESSION-HANDOFF-2026-11-13.md` 的顺序读取项目状态，按“明天第一工作包”准备新的 W3 recovery-binding 只读包，优先解决 PostgreSQL DB role/metadata 查询阻塞；不要重放任何 v1-v6 已消费包，不读取密码或其他环境变量。正式部署、备份和恢复保持 HOLD，新的越界动作先提交准确批准包。
