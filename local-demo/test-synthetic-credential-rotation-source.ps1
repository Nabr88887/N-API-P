$ErrorActionPreference = 'Stop'

$helper = Join-Path $PSScriptRoot '.runtime/synthetic-credential-rotation.ps1'
$lifecycle = Join-Path $PSScriptRoot 'certificate-lifecycle.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    $runtime = Join-Path $PSScriptRoot '.runtime'
    $remainingBackups = @(Get-ChildItem -LiteralPath $runtime -Directory -Force | Where-Object {
        $_.Name -match '^rotation-backup-[0-9a-f]{32}$'
    })
    if ($remainingBackups.Count -ne 0) {
        throw 'synthetic credential rotation helper is missing while retained backup remains'
    }
    Write-Host 'Synthetic credential rotation cleanup state passed.'
    exit 0
}
if (-not (Test-Path -LiteralPath $lifecycle -PathType Leaf)) {
    throw 'certificate lifecycle implementation is missing'
}
$source = Get-Content -Raw -LiteralPath $helper
$lifecycleSource = Get-Content -Raw -LiteralPath $lifecycle
$portalConfigSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '.runtime/portal.cnf')
$mockConfigSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '.runtime/mock.cnf')

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors) | Out-Null
Assert-True ($errors.Count -eq 0) 'synthetic credential rotation helper has parse errors'
Assert-True ($source.Contains(". (Join-Path `$scriptRoot 'recovery-boundary.ps1')", [StringComparison]::Ordinal)) 'helper does not import the project recovery boundary'
Assert-True (-not ($source -match '(?m)^function Invoke-Process\b')) 'helper defines a raw process-output escape hatch'
Assert-True (-not ($source -match '\.(?:Stdout|Stderr)\b')) 'helper reads raw process output outside the recovery boundary'
Assert-True ($source.Contains("`$progressArguments = if (`$Arguments.Count -gt 0 -and `$Arguments[0] -ceq 'up')", [StringComparison]::Ordinal)) 'Compose boundary does not scope quiet progress to service recreation'
Assert-True ($source.Contains("'--progress', 'quiet'", [StringComparison]::Ordinal)) 'service recreation does not suppress Compose lifecycle output'
Assert-True ($source.Contains('$composeArguments = @(''compose'', ''--ansi'', ''never'') + $progressArguments', [StringComparison]::Ordinal)) 'Compose progress options are not applied before the env-file boundary'
Assert-True (-not $lifecycleSource.Contains('Write-Host', [StringComparison]::Ordinal)) 'certificate lifecycle emits content outside the recovery boundary'
Assert-True ($portalConfigSource.Contains('basicConstraints=critical,CA:TRUE', [StringComparison]::Ordinal) -and $mockConfigSource.Contains('basicConstraints=critical,CA:TRUE', [StringComparison]::Ordinal)) 'renewed trust certificate is not marked as a CA'
Assert-True ($source.Contains('psql -h db ', [StringComparison]::Ordinal)) 'TCP verifier does not use the Compose database service host'
Assert-True (-not $source.Contains('psql -h 127.0.0.1', [StringComparison]::Ordinal)) 'TCP verifier uses the database container loopback trust path'
Assert-True ($source.Contains('password authentication failed for user', [StringComparison]::Ordinal)) 'TCP rejection verifier does not classify the allowlisted authentication failure'
Assert-True ($source.Contains("`$allowed = if (`$ExpectedResult -ceq 'rejected') { 'rejected' } else { 'verified' }", [StringComparison]::Ordinal)) 'TCP result mapping does not require the fixed rejected result'
Assert-True ($source.Contains("Invoke-PsqlTCP `$Password 'SELECT 1;' 'rejected'", [StringComparison]::Ordinal)) 'TCP rejection assertion does not request the rejected result contract'
Assert-True ($source.Contains("ConvertTo-LocalDemoServiceArray -Services `$recreatedServices.ToArray()", [StringComparison]::Ordinal)) 'rollback does not flatten and validate the recreated service list'
Assert-True (-not ($source -match "rotation-backup-' \+ \[Guid\]")) 'helper creates a new backup instead of taking over the retained recovery evidence'
Assert-True ($source.Contains('$certStateChanged = $false', [StringComparison]::Ordinal)) 'helper does not track certificate mutation for rollback'
Assert-True ($source.Contains('Assert-CertificateForRenewal', [StringComparison]::Ordinal)) 'helper preflight still requires unexpired certificates before renewal'
Assert-True (-not ($source -match "Assert-Certificate \(Join-Path \$tls 'portal\.crt'\).*? 0")) 'helper preflight still calls strict certificate validity for portal'
Assert-True ($source.Contains('[switch]$AllowExpired', [StringComparison]::Ordinal)) 'runtime boundary cannot validate rollback certificates structurally'
Assert-True ($source.Contains('for ($attempt = 1; $attempt -le 30; $attempt++)', [StringComparison]::Ordinal)) 'upstream TLS verification has no bounded service-readiness retry'
Assert-True ($source.Contains("'curlimages/curl:8.16.0', '--cacert', '/tmp/mock.crt'", [StringComparison]::Ordinal)) 'upstream TLS verification does not invoke curl directly'
Assert-True ($source.Contains("-Arguments @('run', '--rm'", [StringComparison]::Ordinal)) 'upstream TLS verification does not invoke the Docker run subcommand'
Assert-True (-not $source.Contains("'-sS'", [StringComparison]::Ordinal)) 'upstream TLS verification allows curl diagnostics into stderr'
Assert-True ($source.Contains("'--stderr', '/dev/null'", [StringComparison]::Ordinal)) 'upstream TLS verification does not suppress curl diagnostics at the process boundary'
Assert-True ($source.Contains("-AllowedStandardOutput @('404', '000')", [StringComparison]::Ordinal)) 'upstream TLS verification does not allow bounded transient status'
Assert-True ($source.Contains('$result = Invoke-ContentFreeProcess', [StringComparison]::Ordinal)) 'upstream TLS verification drops the process result before validation'
Assert-True (-not $source.Contains('RECOVERY_PROBE_DIAG_', [StringComparison]::Ordinal)) 'helper emits temporary diagnostic output'
Assert-True ($source.Contains('$allowExpired = $MinimumCertificateSeconds -eq 0', [StringComparison]::Ordinal)) 'runtime boundary does not distinguish rollback certificate validity'
Assert-True ($source.Contains('-AllowExpired:$allowExpired', [StringComparison]::Ordinal)) 'runtime boundary does not allow expired rollback certificates'
Assert-True ($source -match '(?s)if \(-not \$allowExpired\) \{\s*Invoke-PortalTLS') 'runtime boundary probes expired rollback TLS instead of deferring to the independent verifier'
Assert-True ($source -match '(?s)function Get-ComposeContainerID\(\[string\]\$Service\) \{.*?Invoke-DockerBoundary.*?label=com\.docker\.compose\.project=n-api-p-local-demo.*?label=com\.docker\.compose\.service=.*?status=running.*?\{\{\.ID\}\}') 'helper service identity query still depends on Compose env-file parsing'
$helperIdentityStart = $source.IndexOf('function Get-ComposeContainerID', [StringComparison]::Ordinal)
$helperIdentityEnd = $source.IndexOf('function Get-DockerInspectSafe', $helperIdentityStart, [StringComparison]::Ordinal)
$helperIdentityBlock = $source.Substring($helperIdentityStart, $helperIdentityEnd - $helperIdentityStart)
Assert-True (-not $helperIdentityBlock.Contains('Invoke-ComposeBoundary', [StringComparison]::Ordinal)) 'helper service identity query calls the Compose env-file boundary'
Assert-True ($source -match '(?s)function Recreate-Service\b.*?recreatedServices\.Add\(\$Service\).*?Invoke-ComposeBoundary') 'helper records a possibly recreated service only after the operation returns'
Assert-True ($source -match '(?s)if \(\$certificateMutationAttempted\) \{.*?Restore-File \$backupPortalCertificate') 'rollback does not restore certificate state after a mutation attempt'
Assert-True (-not $source.Contains('Remove-Item -LiteralPath $backupRoot', [StringComparison]::Ordinal)) 'helper deletes rollback evidence inside the transactional recovery path'

$failurePhases = @([regex]::Matches($source, '(?m)^\s*\$failurePhase = ''([A-Z_]+)''\s*$') | ForEach-Object {
    $_.Groups[1].Value
} | Sort-Object -Unique)
$expectedFailurePhases = @(
    'POST_VERIFY_DATABASE_AUTH',
    'POST_VERIFY_RUNTIME',
    'POST_VERIFY_UPSTREAM_TLS',
    'PREFLIGHT_DATABASE_AUTH',
    'PREFLIGHT_RETAINED_BACKUP',
    'PREFLIGHT_RUNTIME_ENV',
    'PREFLIGHT_SERVICE_BOUNDARY',
    'PREFLIGHT_SOURCE_BOUNDARY',
    'ROTATION_CERTIFICATES',
    'ROTATION_DATABASE',
    'ROTATION_RUNTIME_ENV',
    'SERVICE_RECREATE'
)
Assert-True (($failurePhases -join ',') -ceq ($expectedFailurePhases -join ',')) 'helper failure phases are not the fixed content-free contract'

$rollbackFailurePhases = @([regex]::Matches($source, '(?m)^\s*\$rollbackFailurePhase = ''([A-Z_]+)''\s*$') | ForEach-Object {
    $_.Groups[1].Value
} | Sort-Object -Unique)
$expectedRollbackFailurePhases = @(
    'ROLLBACK_CERTIFICATES',
    'ROLLBACK_DATABASE',
    'ROLLBACK_DATABASE_AUTH',
    'ROLLBACK_RUNTIME_BOUNDARY',
    'ROLLBACK_RUNTIME_ENV',
    'ROLLBACK_SERVICES'
)
Assert-True (($rollbackFailurePhases -join ',') -ceq ($expectedRollbackFailurePhases -join ',')) 'helper rollback phases are not the fixed content-free contract'
Assert-True (-not $source.Contains('$rollbackOK = $true', [StringComparison]::Ordinal)) 'helper still treats a pre-mutation failure as a successful rollback by default'
Assert-True ($source.Contains('$mutationAttempted = $false', [StringComparison]::Ordinal)) 'helper does not track whether a mutation was attempted'
Assert-True ($source.Contains('for ($attempt = 1; $attempt -le 30; $attempt++)', [StringComparison]::Ordinal)) 'upstream TLS verification has no bounded service-readiness retry'
Assert-True ($source.Contains("'curlimages/curl:8.16.0', '--cacert', '/tmp/mock.crt'", [StringComparison]::Ordinal)) 'upstream TLS verification does not invoke curl directly'
Assert-True ($source.Contains('function Assert-UpstreamTLS([string]$DockerPath, [string]$TrustCarrierPath)', [StringComparison]::Ordinal)) 'upstream TLS verification relies on a dynamic process path variable'
Assert-True (-not $source.Contains('RECOVERY_PROBE_', [StringComparison]::Ordinal)) 'helper emits temporary diagnostic output'
Assert-True (-not ($source -match '(?s)Assert-UpstreamTLS.*?Invoke-ContentFreeProcess.*?\| Out-Null')) 'upstream TLS verification pipes away the boundary result'
Assert-True (-not $source.Contains('RECOVERY_PROBE_', [StringComparison]::Ordinal)) 'helper emits temporary diagnostic output'
Assert-True (-not $source.Contains('$script:ContentFreeProcessCaptures[$probeName]', [StringComparison]::Ordinal)) 'upstream TLS verification reads the wrong script scope'
Assert-True ($source -match '(?s)\$failurePhase = ''ROTATION_DATABASE''.*?\$mutationAttempted = \$true\s*\$dbRotationAttempted = \$true\s*\$alterSQL = .*?Assert-PsqlSuccess') 'helper does not mark mutation intent before the first external mutation'
Assert-True ($source.Contains('$rollbackCompleted = $false', [StringComparison]::Ordinal)) 'helper does not require positive rollback completion'
Assert-True ($source.Contains("Write-Output ('RECOVERY_FAILED_{0}_NO_MUTATION' -f `$failurePhase)", [StringComparison]::Ordinal)) 'helper does not distinguish a pre-mutation failure from a completed rollback'
Assert-True ($source.Contains("Write-Output ('RECOVERY_FAILED_{0}_ROLLED_BACK' -f `$failurePhase)", [StringComparison]::Ordinal)) 'helper does not report the fixed primary failure phase after a verified rollback'
Assert-True ($source.Contains("Write-Output ('RECOVERY_FAILED_{0}_{1}_FAILED' -f `$failurePhase, `$rollbackFailurePhase)", [StringComparison]::Ordinal)) 'helper does not report primary and rollback failure phases independently'

Write-Host 'Synthetic credential rotation source tests passed.'
