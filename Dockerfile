FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend-build

WORKDIR /workspace/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci \
    --ignore-scripts \
    --registry=https://registry.npmjs.org/ \
    --replace-registry-host=always \
    --cache=/tmp/npm-cache

COPY frontend/ ./
RUN npm run build

FROM golang:1.25.12@sha256:d2e20dc1b35aefd666909163e4ace41efb521359aa2ce31fff59d86837050f6f AS go-build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GOPROXY=https://proxy.golang.org
ARG VERSION
ARG REVISION

ENV GOSUMDB="sum.golang.org https://sum.golang.google.cn"

WORKDIR /workspace/backend

COPY backend/go.mod backend/go.sum ./
RUN case "$GOPROXY" in \
      "https://proxy.golang.org"|"https://goproxy.cn") ;; \
      *) exit 1 ;; \
    esac && \
    GOPROXY="$GOPROXY" go mod download && \
    GOPROXY="$GOPROXY" go mod verify

COPY backend/ ./
COPY --from=frontend-build /workspace/backend/internal/web/static/build ./internal/web/static/build

RUN case "$VERSION" in ""|latest|*placeholder*|*[!A-Za-z0-9._-]*) exit 1 ;; esac && \
    case "$REVISION" in ""|*[!0-9a-f]*) exit 1 ;; esac && \
    test "${#REVISION}" -eq 40 && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/n-api-p ./cmd/n-api-p && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/n-api-p-healthcheck ./cmd/n-api-p-healthcheck && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/n-api-p-migrate ./cmd/n-api-p-migrate

FROM scratch

ARG VERSION
ARG REVISION

LABEL org.opencontainers.image.title="N-API-P" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"

COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-build /out/n-api-p /n-api-p
COPY --from=go-build /out/n-api-p-healthcheck /n-api-p-healthcheck
COPY --from=go-build /out/n-api-p-migrate /n-api-p-migrate

# The startup contract reads root-owned 0400 secret mounts directly. Runtime
# configuration must add the hardening controls documented in deploy/RUNBOOK.md.
USER 0:0

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 CMD ["/n-api-p-healthcheck"]

ENTRYPOINT ["/n-api-p"]
