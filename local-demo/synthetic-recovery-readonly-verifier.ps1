param(
    [Parameter(Mandatory)]
    [ValidateSet('Recovered', 'RolledBack')]
    [string]$ExpectedState,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{12,64}$')]
    [string]$ExpectedDatabaseContainerID,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')]
    [string]$ExpectedDatabaseVolumeID
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'SilentlyContinue'
$verificationPhase = 'VERIFY_SETUP'

function Invoke-DockerBoundary {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [string]$InputText,
        [string[]]$AllowedStandardOutput,
        [string]$AllowedStandardOutputPattern,
        [string[]]$AllowedStandardError,
        [string[]]$AllowedStandardErrorPattern,
        [string]$SafeOutputKind,
        [string]$CaptureStandardOutputAs
    )

    $parameters = @{ FileName = $script:docker; Arguments = $Arguments }
    foreach ($name in @('InputText', 'AllowedStandardOutput', 'AllowedStandardOutputPattern', 'AllowedStandardError', 'AllowedStandardErrorPattern', 'SafeOutputKind', 'CaptureStandardOutputAs')) {
        if ($PSBoundParameters.ContainsKey($name)) {
            $parameters[$name] = $PSBoundParameters[$name]
        }
    }
    return Invoke-ContentFreeProcess @parameters
}

function Invoke-ComposeBoundary {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [string]$InputText,
        [string[]]$AllowedStandardOutput,
        [string]$AllowedStandardOutputPattern,
        [string[]]$AllowedStandardError,
        [string[]]$AllowedStandardErrorPattern,
        [string]$SafeOutputKind
    )

    $composeArguments = @(
        'compose', '--ansi', 'never',
        '--env-file', $script:envFile, '-f', $script:compose
    ) + $Arguments
    $parameters = @{ Arguments = $composeArguments }
    foreach ($name in @('InputText', 'AllowedStandardOutput', 'AllowedStandardOutputPattern', 'AllowedStandardError', 'AllowedStandardErrorPattern', 'SafeOutputKind')) {
        if ($PSBoundParameters.ContainsKey($name)) {
            $parameters[$name] = $PSBoundParameters[$name]
        }
    }
    return Invoke-DockerBoundary @parameters
}

function Get-ComposeContainerID([string]$Service) {
    if ($Service -cnotin @('db', 'mock', 'app', 'proxy')) {
        throw 'service identity request rejected'
    }
    $result = Invoke-DockerBoundary `
        -Arguments @(
            'ps',
            '--filter', 'label=com.docker.compose.project=n-api-p-local-demo',
            '--filter', ('label=com.docker.compose.service=' + $Service),
            '--filter', 'status=running',
            '--format', '{{.ID}}'
        ) `
        -AllowedStandardOutputPattern '^[0-9a-f]{12,64}$' `
        -SafeOutputKind 'ContainerID'
    return [string]$result.SafeValue
}

function Get-DockerInspectSafe(
    [string]$ContainerID,
    [string]$Format,
    [string]$AllowedPattern,
    [string]$SafeOutputKind
) {
    $result = Invoke-DockerBoundary `
        -Arguments @('inspect', '--format', $Format, $ContainerID) `
        -AllowedStandardOutputPattern $AllowedPattern `
        -SafeOutputKind $SafeOutputKind
    return $result.SafeValue
}

function Get-RuntimePassword([string]$EnvironmentPath) {
    $lines = [IO.File]::ReadAllLines($EnvironmentPath)
    if ($lines.Count -ne 2) {
        throw 'runtime environment shape drift'
    }
    $passwordLine = @($lines | Where-Object { $_ -match '^DEMO_DB_PASSWORD=' })
    $databaseURLLine = @($lines | Where-Object { $_ -match '^DEMO_DATABASE_URL=' })
    if ($passwordLine.Count -ne 1 -or $passwordLine[0] -notmatch '^DEMO_DB_PASSWORD=([A-Za-z0-9]{40})$') {
        throw 'runtime environment contract drift'
    }
    $password = $Matches[1]
    if ($databaseURLLine.Count -ne 1 -or
        $databaseURLLine[0] -notmatch '^DEMO_DATABASE_URL=postgres://n_api_p_demo:([A-Za-z0-9]{40})@db:5432/n_api_p_demo\?sslmode=disable$' -or
        $Matches[1] -cne $password) {
        throw 'runtime database URL contract drift'
    }
    return $password
}

function Test-FileEquality([string]$LeftPath, [string]$RightPath) {
    if (-not (Test-Path -LiteralPath $LeftPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $RightPath -PathType Leaf)) {
        return $false
    }
    return Test-LocalDemoByteEquality `
        ([IO.File]::ReadAllBytes($LeftPath)) `
        ([IO.File]::ReadAllBytes($RightPath))
}

function Initialize-RetainedBackup {
    $candidates = @(Get-ChildItem -LiteralPath $script:runtime -Directory -Force | Where-Object {
        $_.Name -match '^rotation-backup-[0-9a-f]{32}$'
    })
    if ($candidates.Count -ne 1 -or ($candidates[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'retained rotation backup boundary drift'
    }
    $script:backupRoot = $candidates[0].FullName
    $script:backupEnv = Join-Path $script:backupRoot 'demo.env'
    $script:backupPortalCertificate = Join-Path $script:backupRoot 'portal.crt'
    $script:backupPortalKey = Join-Path $script:backupRoot 'portal.key'
    $script:backupMockCertificate = Join-Path $script:backupRoot 'mock.crt'
    $script:backupMockKey = Join-Path $script:backupRoot 'mock.key'
    $script:backupTrust = Join-Path $script:backupRoot 'ca-certificates.crt'

    $expectedNames = @('ca-certificates.crt', 'demo.env', 'mock.crt', 'mock.key', 'portal.crt', 'portal.key')
    $entries = @(Get-ChildItem -LiteralPath $script:backupRoot -Force)
    $actualNames = @($entries | Sort-Object Name | Select-Object -ExpandProperty Name)
    if ($entries.Count -ne $expectedNames.Count -or ($actualNames -join ',') -cne ($expectedNames -join ',')) {
        throw 'retained rotation backup shape drift'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $entry.Length -le 0) {
            throw 'retained rotation backup file drift'
        }
    }
}

function Assert-CleanWorkingRevision {
    Invoke-ContentFreeProcess `
        -FileName $script:git `
        -Arguments @('rev-parse', 'HEAD') `
        -AllowedStandardOutput @($script:expectedRevision) | Out-Null
}

function Assert-ExpectedImage {
    Invoke-DockerBoundary `
        -Arguments @('image', 'inspect', '--format', '{{.Id}}', 'n-api-p-local-demo:latest') `
        -AllowedStandardOutput @($script:expectedImageID) | Out-Null
}

function Assert-NoGateBCandidates {
    Invoke-DockerBoundary `
        -Arguments @('ps', '-a', '--format', '{{.Names}}|{{.Image}}') `
        -AllowedStandardOutputPattern '(?is)^(?!.*(?:rc.?1|rc.?2|gate.?b|candidate)).*$' | Out-Null
}

function Assert-RunningService([string]$Service, [string]$ContainerID) {
    $status = Get-DockerInspectSafe $ContainerID '{{.State.Status}}' '^[a-z]+$' 'Status'
    if ($status -cne 'running') {
        throw "service $Service is not running"
    }
}

function Assert-DatabaseHealth([string]$ContainerID) {
    $health = Get-DockerInspectSafe $ContainerID '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' '^[a-z]+$' 'Status'
    if ($health -cne 'healthy') {
        throw 'database is not healthy'
    }
}

function Assert-AppBoundary([string]$ContainerID) {
    Get-DockerInspectSafe $ContainerID '{{range .Config.Env}}{{if eq . "N_API_P_NEWAPI_BASE_URL=https://demo-newapi:8443"}}configured{{end}}{{end}}' '^configured$' 'Configured' | Out-Null
    Get-DockerInspectSafe $ContainerID '{{range .Config.Env}}{{if eq . "SSL_CERT_FILE=/run/demo-tls/ca-certificates.crt"}}configured{{end}}{{end}}' '^configured$' 'Configured' | Out-Null
}

function Assert-ExpectedPublication([string]$ContainerID, [bool]$Published) {
    $actual = Get-DockerInspectSafe $ContainerID '{{json .HostConfig.PortBindings}}' '^(?:\{.*\}|<no value>|null)?$' 'PortBindings'
    if ([bool]$actual -ne $Published) {
        throw 'container publication drift'
    }
}

function Invoke-PsqlTCP(
    [string]$Password,
    [ValidateSet('one', 'rejected')]
    [string]$ExpectedResult
) {
    $shell = if ($ExpectedResult -ceq 'one') {
        'IFS= read -r PGPASSWORD; export PGPASSWORD PGCONNECT_TIMEOUT=5 LC_ALL=C; output="$(psql -h db -U n_api_p_demo -d n_api_p_demo -v ON_ERROR_STOP=1 -Atq 2>/dev/null)"; code=$?; unset PGPASSWORD; [ "$code" -eq 0 ] || exit 40; [ "$output" = "1" ] || exit 41; printf verified'
    } else {
        'IFS= read -r PGPASSWORD; export PGPASSWORD PGCONNECT_TIMEOUT=5 LC_ALL=C; output="$(psql -h db -U n_api_p_demo -d n_api_p_demo -v ON_ERROR_STOP=1 -Atq 2>&1)"; code=$?; unset PGPASSWORD; [ "$code" -ne 0 ] || exit 42; case "$output" in *"password authentication failed for user \"n_api_p_demo\""*) printf rejected ;; *) exit 43 ;; esac'
    }
    $allowed = if ($ExpectedResult -ceq 'one') { 'verified' } else { 'rejected' }
    Invoke-ComposeBoundary `
        -Arguments @('exec', '-T', 'db', 'sh', '-c', $shell) `
        -InputText ($Password + "`nSELECT 1;`n") `
        -AllowedStandardOutput @($allowed) | Out-Null
}

function Assert-UpstreamTLS([string]$DockerPath, [string]$TrustCarrierPath) {
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $retry = $false
        try {
            $result = Invoke-ContentFreeProcess `
                -FileName $DockerPath `
                -Arguments @('run', '--rm', '--pull', 'never', '--network', 'n-api-p-local-demo_default', '--mount', "type=bind,source=$TrustCarrierPath,target=/tmp/mock.crt,readonly", 'curlimages/curl:8.16.0', '--cacert', '/tmp/mock.crt', '--stderr', '/dev/null', '-s', '-o', '/dev/null', '-w', '%{http_code}', 'https://demo-newapi:8443/') `
                -ExitCodeMode 'any' `
                -AllowedStandardOutput @('404', '000') `
                -SafeOutputKind 'HttpStatusCode' `
                -MaximumOutputBytes 64 `
                -TimeoutMilliseconds 10000
            if ($result.SafeValue -ceq '404') { return }
            if ($result.SafeValue -ceq '000') {
                $retry = $true
            } else {
                throw 'upstream TLS probe failed'
            }
        } catch {
            $retry = $true
        }
        if ($retry -and $attempt -lt 30) {
            Start-Sleep -Seconds 1
        }
    }
    throw 'upstream TLS probe failed'
}

function Assert-RuntimeBoundary {
    $serviceIDs = @{}
    foreach ($service in @('db', 'mock', 'app', 'proxy')) {
        $serviceIDs[$service] = Get-ComposeContainerID $service
        Assert-RunningService $service $serviceIDs[$service]
    }
    if ($serviceIDs['db'] -cne $ExpectedDatabaseContainerID) {
        throw 'database container identity changed'
    }
    Assert-DatabaseHealth $serviceIDs['db']
    Assert-AppBoundary $serviceIDs['app']
    Assert-ExpectedPublication $serviceIDs['app'] $false
    Assert-ExpectedPublication $serviceIDs['mock'] $false
    Assert-ExpectedPublication $serviceIDs['proxy'] $true
    $currentVolumeID = Get-DockerInspectSafe $serviceIDs['db'] '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' 'VolumeID'
    if ($currentVolumeID -cne $ExpectedDatabaseVolumeID) {
        throw 'database volume identity changed'
    }
    if (-not (Test-Path -LiteralPath $script:artifact -PathType Leaf) -or (Get-Item -LiteralPath $script:artifact).Length -le 0) {
        throw 'retained release artifact missing'
    }
    if ((Test-Path -LiteralPath (Join-Path $script:runtime 'newapi-rehearsal')) -or
        (Test-Path -LiteralPath (Join-Path $script:runtime 'carrier'))) {
        throw 'carrier directory exists'
    }
}

try {
    $script:scriptRoot = (Resolve-Path $PSScriptRoot).Path
    $script:runtime = Join-Path $script:scriptRoot '.runtime'
    $script:envFile = Join-Path $script:runtime 'demo.env'
    $script:compose = Join-Path $script:scriptRoot 'docker-compose.yml'
    $script:tls = Join-Path $script:runtime 'tls'
    $script:trustCarrier = Join-Path $script:tls 'ca-certificates.crt'
    $script:artifact = Join-Path (Resolve-Path (Join-Path $script:scriptRoot '..')).Path 'tmp/n-api-p-release-delta'
    $script:expectedRevision = 'e284b5368bed4941b5b4fc30b5c2668e9bec679d'
    $script:expectedImageID = 'sha256:a3295392b65e8f3950ca9d9fea015330c7be26be7dabdf316fc46a96277edd37'
    $script:docker = (Get-Command docker -ErrorAction Stop).Source
    $script:git = (Get-Command git -ErrorAction Stop).Source
    $script:openssl = (Get-Command openssl -ErrorAction Stop).Source
    . (Join-Path $script:scriptRoot 'recovery-boundary.ps1')
    . (Join-Path $script:scriptRoot 'certificate-lifecycle.ps1')
    $verificationStateToken = if ($ExpectedState -ceq 'RolledBack') {
        'ROLLED_BACK'
    } else {
        'RECOVERED'
    }

    $verificationPhase = 'VERIFY_RETAINED_BACKUP'
    Initialize-RetainedBackup

    $verificationPhase = 'VERIFY_RUNTIME_ENV'
    $activePassword = Get-RuntimePassword $script:envFile
    $backupPassword = Get-RuntimePassword $script:backupEnv
    if ($ExpectedState -ceq 'Recovered' -and $activePassword -ceq $backupPassword) {
        throw 'credential did not rotate'
    }
    if ($ExpectedState -ceq 'RolledBack' -and $activePassword -cne $backupPassword) {
        throw 'credential did not roll back'
    }

    $verificationPhase = 'VERIFY_SOURCE_BOUNDARY'
    Assert-CleanWorkingRevision
    Assert-ExpectedImage
    Assert-NoGateBCandidates

    $verificationPhase = 'VERIFY_SERVICE_BOUNDARY'
    Assert-RuntimeBoundary

    $verificationPhase = 'VERIFY_ROLLBACK_FILES'
    if ($ExpectedState -ceq 'RolledBack') {
        foreach ($pair in @(
            @($script:envFile, $script:backupEnv),
            @((Join-Path $script:tls 'portal.crt'), $script:backupPortalCertificate),
            @((Join-Path $script:tls 'portal.key'), $script:backupPortalKey),
            @((Join-Path $script:tls 'mock.crt'), $script:backupMockCertificate),
            @((Join-Path $script:tls 'mock.key'), $script:backupMockKey),
            @($script:trustCarrier, $script:backupTrust)
        )) {
            if (-not (Test-FileEquality $pair[0] $pair[1])) {
                throw 'rollback file mismatch'
            }
        }
    }

    $verificationPhase = 'VERIFY_DATABASE_AUTH'
    Invoke-PsqlTCP $activePassword 'one'
    if ($ExpectedState -ceq 'Recovered') {
        Invoke-PsqlTCP $backupPassword 'rejected'
    }

    $verificationPhase = 'VERIFY_TLS'
    $minimumCertificateSeconds = if ($ExpectedState -ceq 'Recovered') { 86400 } else { 0 }
    Assert-LocalDemoCertificate -OpenSSL $script:openssl -CertificatePath (Join-Path $script:tls 'portal.crt') -KeyPath (Join-Path $script:tls 'portal.key') -ExpectedHost 'localhost' -MinimumRemainingSeconds $minimumCertificateSeconds
    Assert-LocalDemoCertificate -OpenSSL $script:openssl -CertificatePath (Join-Path $script:tls 'mock.crt') -KeyPath (Join-Path $script:tls 'mock.key') -ExpectedHost 'demo-newapi' -MinimumRemainingSeconds $minimumCertificateSeconds
    Assert-LocalDemoPortalTLS -OpenSSL $script:openssl -CertificatePath (Join-Path $script:tls 'portal.crt') -Path '/health/live'
    Assert-LocalDemoPortalTLS -OpenSSL $script:openssl -CertificatePath (Join-Path $script:tls 'portal.crt') -Path '/health/ready'

    $verificationPhase = 'VERIFY_UPSTREAM_TLS'
    $trustMount = "type=bind,source=$script:trustCarrier,target=/tmp/mock.crt,readonly"
    Assert-UpstreamTLS $script:docker $script:trustCarrier

    Write-Output ('RECOVERY_VERIFY_{0}_PASS' -f $verificationStateToken)
    exit 0
} catch {
    Write-Output ('RECOVERY_VERIFY_{0}_FAILED_{1}' -f $verificationStateToken, $verificationPhase)
    exit 1
}
