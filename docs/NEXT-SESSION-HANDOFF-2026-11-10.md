# N-API-P 下一会话交接摘要

**更新时间：** 2026-11-10（Asia/Shanghai）
**当前状态：** rc.5 已通过 Gate B；Gate C 和正式部署仍保持 HOLD。

## 今天已确定

- 正式上游是服务器上的 stock NewAPI，不使用 local-demo 作为正式证据。
- NewAPI rc.40 不提供已核实的原生 HTTPS listener；用户选择保留上游，采用
  N-API-P 到内部 proxy 的证书校验 HTTPS，proxy 到 NewAPI 的 HTTP 私网边界。
- 该私网边界的只读 route-contract 已通过一次；不得因无拓扑变化重复调用。
- pilot 窗口为 2026-11-10 10:00 至 2026-11-14 10:00（Asia/Shanghai）。
- Gate C 凭据最多一枚、最长 96 小时、仅 `deepseek-v4-flash`、有限配额；必须在
  2026-11-14 10:00 前到期。
- 用户创建的“访问令牌”是账户安全 token，不是项目 API token；不得放入 carrier。
  项目 token 应从 NewAPI `令牌`管理入口取得，并通过 `/api/token/` metadata 核验。
- 本机 Docker healthy；Gate C 本地测试 120/120 通过；没有本地候选容器。

## 明天第一步

1. 读取 `AGENTS.md`、`.codex/handoff.md`、`.codex/STATUS.md`、
   `.codex/APPROVALS.md` 和本文件。
2. 检查 Git HEAD 与工作区，确认没有把真实凭据、连接详情或 local runtime 带入。
3. 仅做当前 runner 的本地测试、Python compile、hash pin 和
   `remote_invoked:false` preflight。
4. 重新核对当前批准边界；没有新的精确远端批准时，不连接服务器、不登录 NewAPI、
   不读取或创建 token。
5. 获得有效批准后，按顺序执行：无凭据 readiness -> operator-only 登录/`/api/user/self`
   -> `/api/token/` metadata -> 唯一项目 token -> root-only carrier 验证。

## 禁止事项

- 不调用旧的 `.codex/gate_c_readiness_20261105.py`。
- 不把账户访问令牌当作上游 Bearer token，不请求完整 key，不把 token 写入聊天、日志、
  Git 或审批记录。
- 不执行模型/API 请求、数据库/迁移、候选启动、部署、服务或 ingress 变更。
- 不因门户浏览器失败直接判断服务器故障；先检查本机 hosts、`18443` 监听和 SSH tunnel。
- 任一 required check 首次失败即停止；不重试、不签发第二枚 token。

## 参考文件

- `.codex/handoff.md`：完整当前交接与批准边界
- `.codex/STATUS.md`：当前事实、验证和 blocker
- `docs/NEWAPI-CREDENTIAL-TYPE-MISMATCH-2026-11-10.md`：严重问题说明
- `docs/PORTAL-TUNNEL-INCIDENT-2026-11-09.md`：门户 tunnel 事故
- `ERR-20261110-NAPI-P-NEWAPI-CREDENTIAL-TYPE-MISMATCH`：本机错误档案
- `PROC-20261110-n-api-p-newapi-credential-flow`：本机过程库
