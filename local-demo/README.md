# Local Demo

This is a disposable, synthetic-only demonstration stack. It is not a pilot,
does not use the Gate B candidate image, and never contacts real NewAPI.

## Start

From PowerShell at the repository root:

```powershell
.\local-demo\start.ps1
```

Open [https://localhost:8443](https://localhost:8443). The certificate is
self-signed and valid for two days. Re-running the script renews an invalid
certificate or one with less than 24 hours remaining, then recreates only its
running consumers and verifies both synthetic TLS paths. Accept the browser
warning only for this local demo. The generated administrator email and
password are written to `local-demo/.runtime/credentials/demo-credentials.txt` and are
never printed by the script.

The demo uses `demo-model` and returns synthetic regular and streaming
responses. The database, credentials, certificates, manifest, and logs stay
under ignored `local-demo/.runtime` or disposable Docker volumes.

Run the focused certificate lifecycle regression from the repository root:

```powershell
.\local-demo\test-certificate-lifecycle.ps1
```

Run the credential-free personal-key revocation verifier regression:

```powershell
.\local-demo\test-personal-key-revocation-verifier.ps1
```

Run the credential-free public NewAPI token-contract verifier regression:

```powershell
.\local-demo\test-newapi-token-contract-verifier.ps1
```

For a read-only check against a local NewAPI origin, dot-source
`newapi-token-contract-verifier.ps1` and call
`Invoke-NewAPIPublicTokenContractCheck`. It follows same-origin Rspack async
chunks, aggregates evidence across chunks, bounds response sizes, and retries
HTTP 429 only within a finite delay/attempt limit. It never requests a
protected endpoint or handles credentials. A rate-limited or truncated walk is
reported as inconclusive rather than as contract absence.

Revocation cleanup must retain the key's lifecycle row with `status=revoked`
and a valid `revoked_at` timestamp, then separately confirm that authentication
with the revoked credential returns HTTP 401. The row must not be required to
disappear from the list.

## Stop and reset

```powershell
.\local-demo\stop.ps1
docker compose --env-file .\local-demo\.runtime\demo.env -f .\local-demo\docker-compose.yml down -v
Remove-Item -Recurse -Force .\local-demo\.runtime
```

The reset command deletes only local-demo volumes and runtime files. It must
not be used against any other Compose project.
