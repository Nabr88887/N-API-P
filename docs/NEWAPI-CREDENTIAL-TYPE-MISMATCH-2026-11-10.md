# NewAPI 凭据类型误判记录

- **日期：** 2026-11-10（Asia/Shanghai）
- **项目：** N-API-P rc.5 Gate C
- **严重级别：** S3：造成明显返工并阻塞 Gate C 凭据阶段
- **状态：** 已缓解，正确项目 API token 仍未创建或核验

## 发生了什么

NewAPI 页面上的“访问令牌”被误认为是 N-API-P 需要的上游 API token。实际
上游 token 是 NewAPI `令牌`管理中的 API token 记录；账户安全页的访问令牌是
另一种账户凭据。错误类型的令牌没有交给 Codex、没有写入服务器或候选 carrier，
也没有被用于模型请求。

## 已核实的区别

安装镜像为 NewAPI `v1.0.0-rc.40`，revision
`0aec08fee811ec6136828fda790551b49e410301`。该 revision 的官方源码显示：

| 用途 | 路由 | 是否是 N-API-P 上游 token |
| --- | --- | --- |
| 账户安全访问令牌 | `/api/user/token` | 否 |
| 项目 API token 列表/详情 | `GET /api/token/`、`GET /api/token/{id}` | 是 |
| 项目 API token 撤销 | `DELETE /api/token/{id}` | 是 |

项目 API token 的 metadata 需要核验 owner、`model_limits`、有限配额、状态和
到期时间；列表和详情返回脱敏 key。不要使用 `POST /api/token/{id}/key`，也不要
在聊天、日志、仓库或审批记录中传输完整 token。

## 影响与边界

- 正确项目 token 尚不存在。当天的 Gate C 凭据授权已因独立的旧 readiness runner
  误调用而 `FAILED / CONSUMED`；明天远端操作前必须取得新的精确批准。
- 当前 pilot 窗口为 2026-11-10 10:00 至 2026-11-14 10:00（Asia/Shanghai）。
- 允许的项目 token 最长 96 小时，且必须不晚于窗口结束；最多创建一枚。
- 先完成无凭据 readiness，再创建项目 API token；首个 required check 失败即停止，
  不重试、不创建替代 key。
- 当前已接受的传输边界是 N-API-P 到内部 proxy 使用证书校验 HTTPS；proxy 到
  stock NewAPI 的 HTTP 仅在已证明私有、未发布的容器网络上允许。
- 不包含模型请求、员工或客户数据、数据库/迁移、候选启动、部署、配置变更、
  ingress 或 Gate D-H。

## 明日处理顺序

1. 先读 `AGENTS.md`、`.codex/handoff.md`、`.codex/STATUS.md` 和
   `.codex/APPROVALS.md`，确认批准仍有效。
2. 只做本地 runner 构建、payload pin、测试和 `remote_invoked:false` preflight；
   不使用旧的 `gate_c_readiness_20261105.py`。
3. 取得新的、边界完整的 Gate C 远端批准后，才执行一次 credential-independent
   readiness；未通过不得登录 NewAPI 或创建 token。
4. readiness 通过后，使用 operator-only 认证查询当前 operator 的 `/api/user/self`
   和 `/api/token/` metadata；创建或识别唯一项目 API token，验证 owner、模型、
   配额、期限、状态和撤销路径，并写入 root-only candidate carrier。
5. 浏览器访问需要先恢复本机 SSH tunnel，再检查门户健康；不要把 tunnel 故障与
   Gate C 上游问题混为一谈。

## 证据

- 官方 rc.40 路由、登录、认证中间件、token controller/model 的只读核验已记录在
  `.codex/STATUS.md`、`.codex/handoff.md` 和 `.codex/APPROVALS.md`。
- 详细错误记录：本机跨会话错误档案 ID
  `ERR-20261110-NAPI-P-NEWAPI-CREDENTIAL-TYPE-MISMATCH`。
- 过程记录：本机跨会话过程库 ID
  `PROC-20261110-n-api-p-newapi-credential-flow`。
