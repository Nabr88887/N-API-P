# N-API-P 操作手册

本手册面向下载源码后进行本地演示、内部试运行和运维交接的人员。它补充
项目根目录的 README，不替代具体环境的安全评估、变更审批和备份恢复方案。

## 1. 先确认使用场景

N-API-P 是一个自行托管的 AI 治理网关：客户端请求先到 N-API-P，再由
N-API-P 通过 HTTPS 访问 NewAPI。上游凭据、审计密钥和数据库连接信息都应
只保留在服务端受保护的运行时环境中。

请先选择下面一种场景：

| 场景 | 是否适合下载后直接运行 | 数据与上游 |
| --- | --- | --- |
| 本地合成演示 | 是，需安装 Docker Desktop、PowerShell 和 OpenSSL | 仅合成数据，不连接真实 NewAPI |
| 内部开发验证 | 需要按项目配置启动 PostgreSQL 和本地服务 | 使用测试环境数据，不使用生产凭据 |
| 内部试运行或生产 | 否，需要完成部署、迁移、密钥和反向代理准备 | 连接受控 PostgreSQL 与 NewAPI |

`local-demo/` 只用于可丢弃的本地演示，不应直接复制成生产配置。真实部署
前请阅读 [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) 和
[`deploy/BACKUP-RESTORE.md`](../deploy/BACKUP-RESTORE.md)。

## 2. 下载源码并确认版本

通过 Git 下载：

```powershell
git clone https://github.com/Nabr88887/N-API-P.git
Set-Location .\N-API-P
git rev-parse --short HEAD
```

也可以在 GitHub 页面选择 `Code` → `Download ZIP`。如果需要复现某次验收，
应使用明确的 commit，而不是依赖可变的分支名称：

```powershell
git checkout <approved-commit>
```

下载源码本身不会创建数据库、管理员、上游连接或生产密钥。不要把真实的
环境文件、密钥文件、浏览器凭据、请求头或审计内容放入仓库目录后再打包。

## 3. 启动本地合成演示

### 3.1 前置条件

- Docker Desktop，且 Docker daemon 正常运行；
- Docker Compose；
- PowerShell；
- OpenSSL 可执行文件在 `PATH` 中。

可以先进行不接触业务数据的工具检查：

```powershell
docker version
docker compose version
openssl version
```

### 3.2 启动

在仓库根目录运行：

```powershell
.\local-demo\start.ps1
```

启动脚本会在 `local-demo/.runtime/` 下生成本地演示所需的证书、合成凭据、
数据库连接配置和运行文件，并启动可丢弃的 Docker Compose 服务。脚本不会
连接真实 NewAPI，也不会使用生产数据。

浏览器访问：

```text
https://localhost:8443
```

该地址使用本地自签名证书，只应在这台电脑的本地演示中接受浏览器警告。
不要把它当成公网或内部正式门户。

演示管理员账号信息保存在：

```text
local-demo/.runtime/credentials/demo-credentials.txt
```

只在本机受保护的终端中读取该文件，不要把内容复制到聊天、Issue、日志、
截图或 Git 提交中。

### 3.3 停止和重置

停止演示服务：

```powershell
.\local-demo\stop.ps1
```

只有在确认本地演示数据可以全部删除时，才执行完整重置：

```powershell
docker compose --env-file .\local-demo\.runtime\demo.env -f .\local-demo\docker-compose.yml down -v
Remove-Item -Recurse -Force .\local-demo\.runtime
```

上述重置命令只适用于 `local-demo`，不要对其他 Compose 项目或生产目录使用。

## 4. 第一次内部部署的顺序

真实部署不应通过公开端口直接暴露应用容器。推荐顺序如下：

1. 准备独立 PostgreSQL，并确认备份和恢复策略；
2. 在仓库外复制 `deploy/n-api-p.env.example`，替换所有占位符；
3. 准备独立的上游令牌文件和审计密钥文件，设置为 root 所有、`0400`，并以
   只读方式挂载；
4. 配置 NewAPI 的 HTTPS 地址、反向代理、内部主机名和操作员访问网段；
5. 在关闭入口的情况下，使用经过批准的 `/n-api-p-migrate` 执行前向迁移；
6. 确认数据库是当前干净 schema 后，使用 `/n-api-p-bootstrap` 创建首个系统管理员；
7. 只在私有容器网络中启动 N-API-P，应用端口不要使用宿主机 `-p` 发布；
8. 通过受限的反向代理验证 Docker health、`/health/live` 和 `/health/ready`；
9. 完成管理界面、模型策略、团队成员、服务账号和审计检查后，再开放内部入口。

迁移和首个管理员初始化都是运维操作，不会由 GitHub 下载或普通应用启动
自动完成。管理员初始化时，数据库连接配置必须通过受保护的运行时环境提供；
账号密码使用不回显输入传给 `/n-api-p-bootstrap`，不要出现在命令行参数、
Shell 历史、日志或聊天中。具体约束以 [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md)
为准。

## 5. 日常管理

登录管理门户后，系统管理员可以根据当前授权范围执行以下工作：

- 查看网关和审计运行状态；
- 创建团队并邀请员工账号；
- 为团队分配成员和角色；
- 创建、停用和轮换服务账号及其访问凭据；
- 配置模型允许列表和请求限制；
- 按团队、账号、模型和采集状态筛选审计元数据；
- 在有明确目的和权限的情况下查看受保护的审计详情。

审计查看应遵循最小权限和业务目的限制。不要为了排查普通请求而导出全部
员工会话，也不要在 Issue、聊天或日志中复制原始提示词、响应、Cookie、
认证头或访问凭据。

## 6. Audit 页面故障处理

真实私有门户与本地测试页面不是同一个入口：

- `https://localhost:18443`：真实私有门户，需要有效登录和受控访问；
- `127.0.0.1:4174/e2e/harness.html`：本地合成测试页面，不代表真实服务状态。

遇到 Audit 页面错误时，按下面顺序处理：

| 现象或分类 | 处理方式 |
| --- | --- |
| Session/认证失效 | 重新登录，然后重新进入 Audit；不要反复刷新已失效的页面状态 |
| 网络请求失败 | 检查浏览器到内部反向代理的连通性和 HTTPS 状态；确认后重试 |
| 数据库不可用 | 仅当服务返回明确的数据库不可用分类时处理；由运维检查 `/health/ready`、容器 health 和结构化事件 |
| 服务器内部错误 | 记录时间、请求 ID、HTTP 状态和稳定错误码，交给服务端排查；不要复制完整响应体 |

页面不应把所有运营健康失败都显示成“Database unavailable”，也不应把会话
过期、网络中断和服务器错误混为同一类。重新登录成功后，应重新加载 Audit
列表和元数据；如果仍失败，保留一次失败时的 HTTP 状态、稳定错误码和请求 ID，
避免上传 Cookie、`Authorization`、真实请求/响应或数据库信息。

## 7. 健康检查和发布后检查

每次内部发布后，至少完成以下检查：

- Docker health 为通过状态；
- `/health/live` 返回进程存活结果；
- `/health/ready` 返回就绪结果，且没有泄露数据库连接信息；
- 未登录请求被拒绝；
- 低权限账号不能读取系统管理员专属健康、指标和审计范围；
- 管理员登录、退出、重新登录和 Audit 列表恢复正常；
- 模型策略、个人用量和一条合成请求的审计元数据符合预期；
- 日志只保留允许的元数据，不包含提示词、响应、密码、Token、Cookie 或认证头。

如果发布失败，先关闭内部入口，再依据兼容性选择回滚到经过批准的不可变
应用镜像或执行备份恢复流程。不要执行破坏性降级迁移，也不要直接把员工切换
到 NewAPI 上游凭据。

## 8. 相关文件

- [项目中文说明](../README.zh-CN.md)
- [部署准备 Runbook](../deploy/RUNBOOK.md)
- [备份与恢复](../deploy/BACKUP-RESTORE.md)
- [Nginx 配置示例](../deploy/nginx/n-api-p.conf.example)
- [环境变量占位符](../deploy/n-api-p.env.example)
