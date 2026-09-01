FROM scratch

# Every executable in this image is built from the current worktree for the
# disposable demo. It must not inherit the Gate B candidate image.
COPY local-demo/.runtime/bin/n-api-p /n-api-p
COPY local-demo/.runtime/bin/n-api-p-healthcheck /n-api-p-healthcheck
COPY local-demo/.runtime/bin/n-api-p-migrate /n-api-p-migrate
COPY local-demo/.runtime/bin/n-api-p-demo-mock /n-api-p-demo-mock
COPY local-demo/.runtime/bin/n-api-p-demo-seed /n-api-p-demo-seed
# Demo-only trust root: the application still performs normal certificate and
# hostname verification, but trusts only this generated local mock CA bundle.
COPY local-demo/.runtime/tls/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER 0:0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/n-api-p"]
