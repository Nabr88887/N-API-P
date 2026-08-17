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

ENV GOSUMDB="sum.golang.org https://sum.golang.google.cn"

WORKDIR /workspace/backend

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
COPY --from=frontend-build /workspace/backend/internal/web/static/build ./internal/web/static/build

RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/n-api-p ./cmd/n-api-p

FROM scratch

ARG VERSION=0.0.0-task-9.4-placeholder

LABEL org.opencontainers.image.title="N-API-P" \
      org.opencontainers.image.version="$VERSION"

COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-build /out/n-api-p /n-api-p

# The current startup contract reads root-owned 0400 secret mounts directly.
USER 0:0

ENTRYPOINT ["/n-api-p"]
