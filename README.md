# N-API-P

[English](README.md) | [简体中文](README.zh-CN.md)

N-API-P is a self-hosted, OpenAI-compatible gateway for routing requests
through NewAPI while keeping upstream credentials on the server. It provides
authentication, model policy, usage attribution, rate limits, audit metadata,
and an embedded administration UI.

N-API-P is an open-source graduation design project created by a student at
the University of South China. It is under active development, and its
features and interfaces may change. The complete project source is released
under the MIT License.

The project is intended for learning, research, and evaluation. It has not
been independently assessed for production use; review and test it in your
own environment before deployment. Use it only in authorized settings and in
compliance with applicable laws and upstream provider terms. This project
description does not add restrictions to the MIT License. The repository does
not contain production credentials, customer data, or provider account
configuration.

## Features

- `GET /v1/models` and `POST /v1/chat/completions`
- Non-streaming and SSE streaming responses
- Tool-call payload support
- Invite-only local accounts and server-side sessions
- Personal API keys and service-account keys
- Global model allowlist and request limits
- PostgreSQL-backed metadata and audit records
- Encrypted raw-content storage with bounded retention
- Embedded React/TypeScript administration UI
- Docker and reverse-proxy examples
- Synthetic local demo with generated credentials

## Architecture

```text
OpenAI-compatible client
          |
          v
      N-API-P
       |    \
       |     +--> NewAPI over HTTPS
       |
       +--------> PostgreSQL
```

The application is stateless with respect to conversations: clients send the
conversation history with each request. The upstream NewAPI token is loaded
from a server-side secret file and is never returned to clients.

## Repository Layout

```text
backend/       Go service, gateway, authentication, audit, and migrations
frontend/      React, TypeScript, Vite, and administration UI
deploy/        Environment and reverse-proxy examples
local-demo/    Synthetic local demonstration stack
```

## Local Development

The backend requires Go and the frontend requires Node.js with npm.

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

The synthetic demo can be started from the repository root:

```powershell
.\local-demo\start.ps1
```

The demo uses generated local credentials and synthetic responses. It does not
contact a real NewAPI service or use production data.

## Deployment Notes

`deploy/n-api-p.env.example` and `deploy/nginx/n-api-p.conf.example` are
placeholder-only examples. Replace all `REPLACE_*` values in an operator-owned
file and keep rendered configuration outside Git.

At minimum, production-like deployments should use:

- PostgreSQL with an appropriate TLS and backup policy
- HTTPS between the gateway and NewAPI
- Separate secret files for the upstream token and audit encryption keys
- A reverse proxy with request-size, timeout, and access controls
- Regular backup and restore verification

The included examples do not create users, initialize a database, or deploy
the service automatically.

## Security

Do not commit:

- API tokens, passwords, private keys, or rendered environment files
- Real prompts, responses, user records, or database dumps
- Local runtime files from `local-demo/.runtime/`

Report security issues privately to the repository maintainer rather than
opening a public issue with sensitive details.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
the full text.
