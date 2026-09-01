$ErrorActionPreference = 'Stop'

$demoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runtime = Join-Path $PSScriptRoot '.runtime'
$source = Join-Path $runtime 'source'
$tls = Join-Path $runtime 'tls'
$bin = Join-Path $runtime 'bin'
$credentials = Join-Path $runtime 'credentials'
New-Item -ItemType Directory -Force -Path $source, $tls, $bin, $credentials | Out-Null

$envFile = Join-Path $runtime 'demo.env'
$migrationMarker = Join-Path $runtime 'migration-complete'
$dbPassword = $null
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^DEMO_DB_PASSWORD=(.+)$') {
            $dbPassword = $Matches[1]
            break
        }
    }
}

function New-SafeValue([int]$length = 32) {
    return ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')).Substring(0, $length)
}

function Assert-NativeSuccess([string]$operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$operation failed with exit code $LASTEXITCODE"
    }
}

if ([string]::IsNullOrWhiteSpace($dbPassword)) {
    $dbPassword = New-SafeValue 40
}
$openssl = (Get-Command openssl -ErrorAction Stop).Source
$certificateLifecycle = Join-Path $PSScriptRoot 'certificate-lifecycle.ps1'
if (-not (Test-Path -LiteralPath $certificateLifecycle -PathType Leaf)) {
    throw 'local demo certificate lifecycle helper is missing'
}
. $certificateLifecycle
$portalConfig = Join-Path $runtime 'portal.cnf'
$mockConfig = Join-Path $runtime 'mock.cnf'
[IO.File]::WriteAllText($portalConfig, "[req]`ndistinguished_name=req_dn`nx509_extensions=v3_req`n[req_dn]`n[v3_req]`nsubjectAltName=DNS:localhost,IP:127.0.0.1`n", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($mockConfig, "[req]`ndistinguished_name=req_dn`nx509_extensions=v3_req`n[req_dn]`n[v3_req]`nsubjectAltName=DNS:demo-newapi`n", [Text.UTF8Encoding]::new($false))
$portalCertificate = Join-Path $tls 'portal.crt'
$portalKey = Join-Path $tls 'portal.key'
$mockCertificate = Join-Path $tls 'mock.crt'
$mockKey = Join-Path $tls 'mock.key'
$trustCarrier = Join-Path $tls 'ca-certificates.crt'
$portalRenewed = Update-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $portalCertificate -KeyPath $portalKey -ConfigPath $portalConfig -CommonName 'localhost' -ExpectedHost 'localhost'
$mockRenewed = Update-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $mockCertificate -KeyPath $mockKey -ConfigPath $mockConfig -CommonName 'demo-newapi' -ExpectedHost 'demo-newapi'
$trustChanged = Sync-LocalDemoTrustCarrier -CertificatePath $mockCertificate -TrustCarrierPath $trustCarrier
$affectedServices = @(Get-LocalDemoAffectedServices -PortalRenewed $portalRenewed -MockRenewed $mockRenewed -TrustChanged $trustChanged)
Assert-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $portalCertificate -KeyPath $portalKey -ExpectedHost 'localhost' -MinimumRemainingSeconds 0
Assert-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $mockCertificate -KeyPath $mockKey -ExpectedHost 'demo-newapi' -MinimumRemainingSeconds 0

$nginxConfig = @"
events {}
http {
  upstream n_api_p_app { server app:8080; }
  server {
    listen 443 ssl;
    server_name localhost;
    ssl_certificate /etc/nginx/tls/portal.crt;
    ssl_certificate_key /etc/nginx/tls/portal.key;
    location / {
      proxy_http_version 1.1;
      proxy_set_header Host `$host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_read_timeout 10m;
      proxy_pass http://n_api_p_app;
    }
  }
}
"@
[IO.File]::WriteAllText((Join-Path $runtime 'nginx.conf'), $nginxConfig, [Text.UTF8Encoding]::new($false))

$compose = Join-Path $PSScriptRoot 'docker-compose.yml'

function Get-LocalDemoContainerID([string]$service) {
    $containerID = @(& docker compose --env-file $envFile -f $compose ps -q $service)
    Assert-NativeSuccess "locate demo $service container"
    if ($containerID.Count -ne 1 -or [string]::IsNullOrWhiteSpace($containerID[0])) {
        return $null
    }
    return $containerID[0].Trim()
}

function Test-LocalDemoStackRunning {
    if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
        return $false
    }
    $runningServices = @(& docker compose --env-file $envFile -f $compose ps --status running --services)
    Assert-NativeSuccess 'inspect running demo services'
    foreach ($requiredService in @('db', 'mock', 'app', 'proxy')) {
        if ($runningServices -notcontains $requiredService) {
            return $false
        }
    }
    return $true
}

function Assert-LocalDemoRuntimeTLS {
    foreach ($path in @('/health/live', '/health/ready')) {
        $verified = $false
        for ($attempt = 1; $attempt -le 20; $attempt++) {
            try {
                Assert-LocalDemoPortalTLS -OpenSSL $openssl -CertificatePath $portalCertificate -Path $path
                $verified = $true
                break
            } catch {
                if ($attempt -eq 20) {
                    throw
                }
                Start-Sleep -Milliseconds 500
            }
        }
        if (-not $verified) {
            throw "verified portal TLS probe failed for $path"
        }
    }

    $appContainerID = Get-LocalDemoContainerID 'app'
    if ([string]::IsNullOrWhiteSpace($appContainerID)) {
        throw 'demo app container is not running'
    }
    $appUpstream = @(& docker inspect --format '{{range .Config.Env}}{{if eq . "N_API_P_NEWAPI_BASE_URL=https://demo-newapi:8443"}}configured{{end}}{{end}}' $appContainerID)
    Assert-NativeSuccess 'verify demo app upstream configuration'
    if (($appUpstream -join '').Trim() -ne 'configured') {
        throw 'demo app is not configured for the synthetic HTTPS mock'
    }
    $appTrust = @(& docker inspect --format '{{range .Config.Env}}{{if eq . "SSL_CERT_FILE=/run/demo-tls/ca-certificates.crt"}}configured{{end}}{{end}}' $appContainerID)
    Assert-NativeSuccess 'verify demo app trust configuration'
    if (($appTrust -join '').Trim() -ne 'configured') {
        throw 'demo app is not configured for the active mock certificate'
    }

    $databaseContainerID = Get-LocalDemoContainerID 'db'
    $databaseHealth = @(& docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $databaseContainerID)
    Assert-NativeSuccess 'verify demo database health'
    if (($databaseHealth -join '').Trim() -ne 'healthy') {
        throw 'demo database is not healthy'
    }

    $trustMount = "type=bind,source=$trustCarrier,target=/etc/ssl/certs/ca-certificates.crt,readonly"
    docker run --rm --pull never --network n-api-p-local-demo_default --mount $trustMount `
        --entrypoint /bin/sh alpine:3.22 -c `
        'response="$(wget -S -T 5 -O /dev/null https://demo-newapi:8443/ 2>&1 || true)"; printf "%s\n" "$response" | grep -Eq "HTTP/[0-9.]+ 404"'
    Assert-NativeSuccess 'verify app-to-mock TLS path'
}

if ($affectedServices.Count -gt 0 -and (Test-LocalDemoStackRunning)) {
    $originalContainerIDs = @{}
    foreach ($service in @('db', 'mock', 'app', 'proxy')) {
        $originalContainerIDs[$service] = Get-LocalDemoContainerID $service
    }
    foreach ($service in $affectedServices) {
        docker compose --env-file $envFile -f $compose up -d --force-recreate --no-deps $service
        Assert-NativeSuccess "recreate affected demo service: $service"
    }
    foreach ($service in @('db', 'mock', 'app', 'proxy')) {
        $currentContainerID = Get-LocalDemoContainerID $service
        if ($affectedServices -notcontains $service -and $currentContainerID -ne $originalContainerIDs[$service]) {
            throw "unaffected demo service was recreated: $service"
        }
        if ($affectedServices -contains $service -and $currentContainerID -eq $originalContainerIDs[$service]) {
            throw "affected demo service was not recreated: $service"
        }
    }
    Assert-LocalDemoRuntimeTLS
    Write-Host ('Renewed local demo TLS and recreated only: ' + ($affectedServices -join ', '))
    Write-Host 'Local demo is available at https://localhost:8443'
    return
}

$demoToken = 'local-demo-' + (New-SafeValue 32)
$tokenPath = Join-Path $source 'newapi-token'
$auditKeyPath = Join-Path $source 'audit-master-key'
if (-not (Test-Path $tokenPath)) {
    [IO.File]::WriteAllText($tokenPath, $demoToken, [Text.UTF8Encoding]::new($false))
}
if (-not (Test-Path $auditKeyPath)) {
    $auditKeyBytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($auditKeyBytes)
    $auditKey = [Convert]::ToBase64String($auditKeyBytes)
    [IO.File]::WriteAllText($auditKeyPath, ('{"active_version":1,"keys":[{"version":1,"key_base64":"' + $auditKey + '"}]}' + "`n"), [Text.UTF8Encoding]::new($false))
}

$created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$manifest = '{"backup_id":"local-demo","created_at":"' + $created + '","migration_version":0,"included_tables":[],"excluded_tables":["public.audit_raw_content"],"encryption_key_version":"local-demo","byte_size":1,"checksum":"sha256:' + ('a' * 64) + '","verification_result":"verified"}'
[IO.File]::WriteAllText((Join-Path $source 'metadata-manifest.json'), ($manifest + "`n"), [Text.UTF8Encoding]::new($false))

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildMount = "type=bind,source=$projectRoot,target=/workspace"
docker run --rm --network none --mount $buildMount -w /workspace/backend `
    -e GOMODCACHE=/workspace/tmp/gomodcache -e GOCACHE=/workspace/tmp/gocache `
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 `
    golang:1.25.12 go build -trimpath -ldflags='-s -w' -o /workspace/local-demo/.runtime/bin/n-api-p ./cmd/n-api-p
Assert-NativeSuccess 'build n-api-p'
docker run --rm --network none --mount $buildMount -w /workspace/backend `
    -e GOMODCACHE=/workspace/tmp/gomodcache -e GOCACHE=/workspace/tmp/gocache `
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 `
    golang:1.25.12 go build -trimpath -ldflags='-s -w' -o /workspace/local-demo/.runtime/bin/n-api-p-healthcheck ./cmd/n-api-p-healthcheck
Assert-NativeSuccess 'build n-api-p-healthcheck'
docker run --rm --network none --mount $buildMount -w /workspace/backend `
    -e GOMODCACHE=/workspace/tmp/gomodcache -e GOCACHE=/workspace/tmp/gocache `
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 `
    golang:1.25.12 go build -trimpath -ldflags='-s -w' -o /workspace/local-demo/.runtime/bin/n-api-p-migrate ./cmd/n-api-p-migrate
Assert-NativeSuccess 'build n-api-p-migrate'
docker run --rm --network none --mount $buildMount -w /workspace/backend `
    -e GOMODCACHE=/workspace/tmp/gomodcache -e GOCACHE=/workspace/tmp/gocache `
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 `
    golang:1.25.12 go build -trimpath -ldflags='-s -w' -o /workspace/local-demo/.runtime/bin/n-api-p-demo-mock ./cmd/n-api-p-demo-mock
Assert-NativeSuccess 'build n-api-p-demo-mock'
docker run --rm --network none --mount $buildMount -w /workspace/backend `
    -e GOMODCACHE=/workspace/tmp/gomodcache -e GOCACHE=/workspace/tmp/gocache `
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 `
    golang:1.25.12 go build -trimpath -ldflags='-s -w' -o /workspace/local-demo/.runtime/bin/n-api-p-demo-seed ./cmd/n-api-p-demo-seed
Assert-NativeSuccess 'build n-api-p-demo-seed'
docker build --pull=false --network none --tag n-api-p-local-demo:latest --file (Join-Path $PSScriptRoot 'Dockerfile') $demoRoot
Assert-NativeSuccess 'build local-demo image'

$databaseUrl = 'postgres://n_api_p_demo:' + $dbPassword + '@db:5432/n_api_p_demo?sslmode=disable'
[IO.File]::WriteAllText($envFile, "DEMO_DB_PASSWORD=$dbPassword`nDEMO_DATABASE_URL=$databaseUrl`n", [Text.UTF8Encoding]::new($false))

Push-Location $PSScriptRoot
try {
    docker compose --env-file $envFile -f $compose up -d db
    Assert-NativeSuccess 'start database'
    if ($affectedServices -contains 'mock') {
        docker compose --env-file $envFile -f $compose up -d --force-recreate --no-deps mock
    } else {
        docker compose --env-file $envFile -f $compose up -d --no-deps mock
    }
    Assert-NativeSuccess 'start mock'
    docker compose --env-file $envFile -f $compose run --rm recovery-init
    Assert-NativeSuccess 'initialize recovery manifest'
    docker compose --env-file $envFile -f $compose run --rm secrets-init
    Assert-NativeSuccess 'initialize demo secrets'
    if (-not (Test-Path $migrationMarker)) {
        docker compose --env-file $envFile -f $compose run --rm migrate
        Assert-NativeSuccess 'run demo migrations'
        [IO.File]::WriteAllText($migrationMarker, "migration_completed`n", [Text.UTF8Encoding]::new($false))
    } else {
        Write-Host 'Demo migrations already completed; skipping migration run.'
    }
    $credentialsPath = Join-Path $credentials 'demo-credentials.txt'
    if (-not (Test-Path $credentialsPath)) {
        docker compose --env-file $envFile -f $compose run --rm --no-deps seed
        Assert-NativeSuccess 'seed demo data'
    } else {
        Write-Host 'Demo data already seeded; preserving existing credentials.'
    }
    $remainingAffectedServices = @($affectedServices | Where-Object { $_ -ne 'mock' })
    if ($remainingAffectedServices.Count -gt 0) {
        docker compose --env-file $envFile -f $compose up -d --force-recreate --no-deps $remainingAffectedServices
        Assert-NativeSuccess ('recreate affected demo services: ' + ($remainingAffectedServices -join ', '))
    } else {
        docker compose --env-file $envFile -f $compose up -d --no-deps app proxy
        Assert-NativeSuccess 'start demo app and proxy'
    }
    Assert-LocalDemoRuntimeTLS
    Write-Host 'Local demo is available at https://localhost:8443'
    Write-Host 'Demo credentials are in local-demo/.runtime/credentials/demo-credentials.txt'
} finally {
    Pop-Location
}
