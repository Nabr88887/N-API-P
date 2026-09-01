$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

$caller = Join-Path $PSScriptRoot 'invoke-synthetic-credential-recovery.ps1'
$verifier = Join-Path $PSScriptRoot 'synthetic-recovery-readonly-verifier.ps1'
Assert-True (Test-Path -LiteralPath $caller -PathType Leaf) 'synthetic recovery caller is missing'
Assert-True (Test-Path -LiteralPath $verifier -PathType Leaf) 'synthetic recovery verifier is missing'

$callerSource = Get-Content -Raw -LiteralPath $caller
$verifierSource = Get-Content -Raw -LiteralPath $verifier
foreach ($entry in @(
    @{ Name = 'caller'; Source = $callerSource },
    @{ Name = 'verifier'; Source = $verifierSource }
)) {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseInput($entry.Source, [ref]$tokens, [ref]$errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "$($entry.Name) has parse errors"
    Assert-True (-not ($entry.Source -match '\.(?:Stdout|Stderr)\b')) "$($entry.Name) reads raw process output"
}

Assert-True ($callerSource.Contains('Invoke-ContentFreeProcess', [StringComparison]::Ordinal)) 'caller bypasses the content-free process boundary'
Assert-True ($callerSource.Contains("-MaximumOutputBytes 512", [StringComparison]::Ordinal)) 'caller output is not tightly bounded'
Assert-True ($callerSource.Contains('-TimeoutMilliseconds 600000', [StringComparison]::Ordinal)) 'caller may terminate the helper before bounded rollback completes'
Assert-True ($callerSource.Contains('[IO.FileAttributes]::ReparsePoint', [StringComparison]::Ordinal)) 'caller does not reject a reparse-point helper or backup'
Assert-True ($callerSource.Contains("-SafeOutputKind 'RecoveryStatus'", [StringComparison]::Ordinal)) 'caller does not validate helper status'
Assert-True ($callerSource.Contains("-SafeOutputKind 'RecoveryVerificationStatus'", [StringComparison]::Ordinal)) 'caller does not validate verifier status'
Assert-True ($callerSource.Contains('Write-Output $result.SafeValue', [StringComparison]::Ordinal)) 'caller does not emit only the validated safe status'
Assert-True (-not $callerSource.Contains('$expectedState.ToUpperInvariant()', [StringComparison]::Ordinal)) 'caller derives verifier status from an incompatible token format'
Assert-True ($callerSource.Contains("`$verificationStateToken = if (`$expectedState -ceq 'RolledBack') {", [StringComparison]::Ordinal)) 'caller does not map rollback state to the fixed verifier token'
Assert-True ($callerSource.Contains("-SafeOutputKind 'ContainerID'", [StringComparison]::Ordinal)) 'caller does not capture the pre-recovery database container identity'
Assert-True ($callerSource.Contains("-SafeOutputKind 'VolumeID'", [StringComparison]::Ordinal)) 'caller does not capture the pre-recovery database volume identity'
Assert-True ($callerSource -match "(?s)'ps',\s*'--filter', 'label=com\.docker\.compose\.project=n-api-p-local-demo'") 'caller does not use the fixed Compose project label for container capture'
Assert-True ($callerSource.Contains("'--filter', 'label=com.docker.compose.service=db'", [StringComparison]::Ordinal)) 'caller does not use the fixed db service label for container capture'
Assert-True ($callerSource -match "(?s)'--filter', 'status=running',\s*'--format', '\{\{\.ID\}\}'") 'caller does not require one running container ID from Docker'
Assert-True (-not $callerSource.Contains("'compose', '--ansi'", [StringComparison]::Ordinal)) 'caller still depends on Compose env-file parsing for pre-recovery identity capture'
Assert-True ($callerSource.Contains("'-ExpectedDatabaseContainerID', `$databaseContainerID", [StringComparison]::Ordinal)) 'caller does not pass the expected database container identity to independent verification'
Assert-True ($callerSource.Contains("'-ExpectedDatabaseVolumeID', `$databaseVolumeID", [StringComparison]::Ordinal)) 'caller does not pass the expected database volume identity to independent verification'
Assert-True ($callerSource -match '(?s)if \(\$recoveryPassed -and \$verificationPassed\) \{.*?\^rotation-backup-\[0-9a-f\]\{32\}\$.*?Remove-Item -LiteralPath \$backupRoot -Recurse -Force.*?Remove-Item -LiteralPath \$helper -Force.*?RECOVERY_CLEANUP_PASS') 'caller cleanup is not gated by both recovery and independent verification'
Assert-True ($callerSource.Contains("Write-Output ('RECOVERY_CLEANUP_FAILED_{0}' -f `$cleanupPhase)", [StringComparison]::Ordinal)) 'caller cleanup does not use a fixed phase failure status'

$callerPhases = @([regex]::Matches($callerSource, '(?m)^\s*\$callerPhase = ''([A-Z_]+)''\s*$') | ForEach-Object {
    $_.Groups[1].Value
} | Sort-Object -Unique)
$expectedCallerPhases = @(
    'CALLER_CAPTURE_DATABASE_CONTAINER',
    'CALLER_CAPTURE_DATABASE_VOLUME',
    'CALLER_EXECUTE_RECOVERY',
    'CALLER_EXECUTE_VERIFICATION',
    'CALLER_SETUP'
)
Assert-True (($callerPhases -join ',') -ceq ($expectedCallerPhases -join ',')) 'caller phases are not the fixed content-free contract'
Assert-True ($callerSource.Contains("Write-Output ('RECOVERY_CALLER_FAILED_{0}' -f `$callerPhase)", [StringComparison]::Ordinal)) 'caller does not emit the fixed phase failure status'

$verificationPhases = @([regex]::Matches($verifierSource, '(?m)^\s*\$verificationPhase = ''([A-Z_]+)''\s*$') | ForEach-Object {
    $_.Groups[1].Value
} | Sort-Object -Unique)
$expectedVerificationPhases = @(
    'VERIFY_DATABASE_AUTH',
    'VERIFY_RETAINED_BACKUP',
    'VERIFY_ROLLBACK_FILES',
    'VERIFY_RUNTIME_ENV',
    'VERIFY_SERVICE_BOUNDARY',
    'VERIFY_SETUP',
    'VERIFY_SOURCE_BOUNDARY',
    'VERIFY_TLS',
    'VERIFY_UPSTREAM_TLS'
)
Assert-True (($verificationPhases -join ',') -ceq ($expectedVerificationPhases -join ',')) 'verifier phases are not the fixed content-free contract'
Assert-True ($verifierSource.Contains('psql -h db ', [StringComparison]::Ordinal)) 'verifier does not use the Compose database service host for TCP authentication'
Assert-True (-not $verifierSource.Contains('psql -h 127.0.0.1', [StringComparison]::Ordinal)) 'verifier uses the database container loopback trust path'
Assert-True ($verifierSource.Contains('password authentication failed for user', [StringComparison]::Ordinal)) 'verifier does not classify fixed authentication rejection'
Assert-True ($verifierSource.Contains('for ($attempt = 1; $attempt -le 30; $attempt++)', [StringComparison]::Ordinal)) 'verifier upstream TLS check has no bounded service-readiness retry'
Assert-True ($verifierSource.Contains("'curlimages/curl:8.16.0', '--cacert', '/tmp/mock.crt'", [StringComparison]::Ordinal)) 'verifier upstream TLS check does not invoke curl directly'
Assert-True ($verifierSource.Contains("-Arguments @('run', '--rm'", [StringComparison]::Ordinal)) 'verifier upstream TLS check does not invoke the Docker run subcommand'
Assert-True (-not $verifierSource.Contains("'-sS'", [StringComparison]::Ordinal)) 'verifier upstream TLS check allows curl diagnostics into stderr'
Assert-True ($verifierSource.Contains("'--stderr', '/dev/null'", [StringComparison]::Ordinal)) 'verifier upstream TLS check does not suppress curl diagnostics at the process boundary'
Assert-True ($verifierSource.Contains("-AllowedStandardOutput @('404', '000')", [StringComparison]::Ordinal)) 'verifier upstream TLS check does not allow bounded transient status'
Assert-True (-not $verifierSource.Contains('RECOVERY_PROBE_', [StringComparison]::Ordinal)) 'verifier emits temporary probe diagnostics'
Assert-True ($verifierSource.Contains("if (`$result.SafeValue -ceq '000')", [StringComparison]::Ordinal)) 'verifier does not classify a transient TLS probe result for retry'
Assert-True ($verifierSource.Contains('function Assert-UpstreamTLS([string]$DockerPath, [string]$TrustCarrierPath)', [StringComparison]::Ordinal)) 'verifier relies on a dynamic process path variable'
Assert-True (-not $verifierSource.Contains('$script:ContentFreeProcessCaptures[$probeName]', [StringComparison]::Ordinal)) 'verifier reads the wrong script scope'
Assert-True (-not ($verifierSource -match '(?s)Assert-UpstreamTLS.*?Invoke-ContentFreeProcess.*?\| Out-Null')) 'verifier pipes away the boundary result'
Assert-True ($verifierSource.Contains("[ValidatePattern('^[0-9a-f]{12,64}$')]", [StringComparison]::Ordinal)) 'verifier does not validate the expected database container identity'
Assert-True ($verifierSource.Contains("[ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')]", [StringComparison]::Ordinal)) 'verifier does not validate the expected database volume identity'
Assert-True ($verifierSource -match '(?s)function Get-ComposeContainerID\(\[string\]\$Service\) \{.*?Invoke-DockerBoundary.*?label=com\.docker\.compose\.project=n-api-p-local-demo.*?label=com\.docker\.compose\.service=.*?status=running.*?\{\{\.ID\}\}') 'verifier service identity query still depends on Compose env-file parsing'
$verifierIdentityStart = $verifierSource.IndexOf('function Get-ComposeContainerID', [StringComparison]::Ordinal)
$verifierIdentityEnd = $verifierSource.IndexOf('function Get-DockerInspectSafe', $verifierIdentityStart, [StringComparison]::Ordinal)
$verifierIdentityBlock = $verifierSource.Substring($verifierIdentityStart, $verifierIdentityEnd - $verifierIdentityStart)
Assert-True (-not $verifierIdentityBlock.Contains('Invoke-ComposeBoundary', [StringComparison]::Ordinal)) 'verifier service identity query calls the Compose env-file boundary'
Assert-True ($verifierSource.Contains("`$serviceIDs['db'] -cne `$ExpectedDatabaseContainerID", [StringComparison]::Ordinal)) 'verifier does not compare the database container identity'
Assert-True ($verifierSource.Contains('`$currentVolumeID -cne `$ExpectedDatabaseVolumeID'.Replace('`$', '$'), [StringComparison]::Ordinal)) 'verifier does not compare the database volume identity'
Assert-True (-not $verifierSource.Contains('$ExpectedState.ToUpperInvariant()', [StringComparison]::Ordinal)) 'verifier derives status from an incompatible token format'
Assert-True ($verifierSource.Contains("`$verificationStateToken = if (`$ExpectedState -ceq 'RolledBack') {", [StringComparison]::Ordinal)) 'verifier does not map rollback state to the fixed status token'
Assert-True ($verifierSource.Contains("Write-Output ('RECOVERY_VERIFY_{0}_PASS' -f `$verificationStateToken)", [StringComparison]::Ordinal)) 'verifier does not emit the fixed success status'
Assert-True ($verifierSource.Contains("Write-Output ('RECOVERY_VERIFY_{0}_FAILED_{1}' -f `$verificationStateToken, `$verificationPhase)", [StringComparison]::Ordinal)) 'verifier does not emit the fixed phase failure status'
Assert-True (-not $verifierSource.Contains("'--progress'", [StringComparison]::Ordinal)) 'verifier Compose boundary passes an incompatible progress option'
Assert-True ($verifierSource -match '(?s)if \(\$ExpectedState -ceq ''RolledBack''\).*?Test-FileEquality') 'rollback verification does not compare retained files in process'
Assert-True ($verifierSource.Contains("`$minimumCertificateSeconds = if (`$ExpectedState -ceq 'Recovered') { 86400 } else { 0 }", [StringComparison]::Ordinal)) 'verifier does not preserve the rollback certificate contract'
Assert-True (-not ($verifierSource -match '(?i)\bALTER\s+ROLE\b|\bMove-Item\b|\bCopy-Item\b|\bRemove-Item\b|\bUpdate-LocalDemoCertificate\b|\bSync-LocalDemoTrustCarrier\b')) 'read-only verifier contains a mutation command'

Write-Host 'Synthetic recovery orchestration source tests passed.'
