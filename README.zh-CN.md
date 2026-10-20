# N-API-P

[English](README.md) | [简体中文](README.zh-CN.md)

N-API-P 是一个可自行托管、兼容 OpenAI API 的 AI 网关，通过 NewAPI 转发
请求，同时将上游凭据保留在服务器端。项目提供身份认证、模型策略、用量归属、
请求速率限制、审计元数据和内嵌管理界面。

N-API-P 是一名南华大学学生的毕业设计项目，采用开源方式开发，完整项目源码以
MIT 许可证发布。目前项目仍在开发中，功能和接口可能发生变化。

本项目主要用于学习、研究和评估，尚未经过独立的生产环境适用性评估；部署前请在
自己的环境中审查并测试。请仅在获得授权的环境中使用，并遵守适用法律法规及上游
服务提供方的条款。本段说明项目定位，不对 MIT 许可证增加额外限制。仓库不包含
生产凭据、客户数据或服务商账号配置。

## 功能

- `GET /v1/models` 和 `POST /v1/chat/completions`
- 非流式和 SSE 流式响应
- 工具调用载荷支持
- 邀请制本地账号和服务端会话
- 个人 API Key 和服务账号 Key
- 全局模型允许列表和请求限制
- 基于 PostgreSQL 的元数据与审计记录
- 加密的原始内容存储和有界保留期限
- 内嵌 React/TypeScript 管理界面
- Docker 和反向代理配置示例
- 使用生成凭据的合成本地演示

## 架构

```text
兼容 OpenAI 的客户端
          |
          v
      N-API-P
       |    \
       |     +--> 通过 HTTPS 连接 NewAPI
       |
       +--------> PostgreSQL
```

应用不会在服务端保存对话状态；客户端每次请求都需要发送对话历史。上游 NewAPI
令牌从服务器端密钥文件加载，不会返回给客户端。

## 仓库目录

```text
backend/       Go 服务、网关、认证、审计和数据库迁移
frontend/      React、TypeScript、Vite 和管理界面
deploy/        环境与反向代理配置示例
local-demo/    使用合成数据的本地演示环境
```

## 本地开发

后端需要 Go；前端需要 Node.js 和 npm。

```powershell
Set-Location .\backend
go test ./...
go vet ./...
go build ./cmd/n-api-p
```

```powershell
Set-Location .\frontend
npm ci
npm run verify
```

在仓库根目录启动合成本地演示：

```powershell
.\local-demo\start.ps1
```

演示环境使用本地生成的凭据和合成响应，不会连接真实 NewAPI 服务，也不会使用生产数据。

## 部署说明

`deploy/n-api-p.env.example` 和 `deploy/nginx/n-api-p.conf.example` 仅包含占位符。
请在由运维人员管理的文件中替换所有 `REPLACE_*` 值，并将渲染后的配置保留在 Git
仓库之外。

生产类部署至少应配置：

- 使用适当 TLS 和备份策略的 PostgreSQL
- 网关与 NewAPI 之间的 HTTPS
- 分离保存的上游令牌和审计加密密钥文件
- 配置请求体大小、超时和访问控制的反向代理
- 定期备份和恢复验证

仓库中的配置示例不会自动创建用户、初始化数据库或部署服务。

## 安全

请勿提交以下内容：

- API 令牌、密码、私钥或渲染后的环境配置文件
- 真实提示词、响应内容、用户记录或数据库转储
- `local-demo/.runtime/` 中的本地运行时文件

请通过私下渠道向仓库维护者报告安全问题，不要在公开 Issue 中披露敏感细节。

## 许可证

本项目采用 MIT 许可证。完整文本见 [LICENSE](LICENSE)。
