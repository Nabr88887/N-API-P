$ErrorActionPreference = 'Stop'

$boundary = Join-Path $PSScriptRoot 'recovery-boundary.ps1'
if (-not (Test-Path -LiteralPath $boundary -PathType Leaf)) {
    throw 'recovery boundary implementation is missing'
}
. $boundary

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-RejectedWithoutCanary(
    [scriptblock]$Operation,
    [string]$ExpectedMessage,
    [string]$Canary
) {
    $actualMessage = $null
    try {
        & $Operation | Out-Null
    } catch {
        $actualMessage = $_.Exception.Message
    }
    Assert-True ($actualMessage -ceq $ExpectedMessage) 'process rejection did not use the stable content-free error'
    Assert-True (-not $actualMessage.Contains($Canary, [StringComparison]::Ordinal)) 'process rejection exposed the canary'
}

$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
$allowed = Invoke-ContentFreeProcess `
    -FileName $pwsh `
    -Arguments @('-NoProfile', '-Command', '[Console]::Out.Write(''approved'')') `
    -AllowedStandardOutput @('approved')
$allowedProperties = @($allowed.PSObject.Properties.Name | Sort-Object)
Assert-True (($allowedProperties -join ',') -ceq 'ExitCode,Status') 'process result exposed fields outside the allowlisted status contract'
Assert-True ($allowed.Status -ceq 'matched' -and $allowed.ExitCode -eq 0) 'allowlisted process output was not accepted'

Invoke-ContentFreeProcess `
    -FileName $pwsh `
    -Arguments @('-NoProfile', '-Command', '[Console]::Out.Write(''captured'')') `
    -AllowedStandardOutput @('captured') `
    -CaptureStandardOutputAs 'test-capture' | Out-Null
Assert-True ((Get-ContentFreeProcessCapture -Name 'test-capture') -ceq 'captured') 'content-free capture accessor did not return the allowlisted value'
Clear-ContentFreeProcessCapture -Name 'test-capture'

$caseCanary = 'APPROVED'
Assert-RejectedWithoutCanary {
    Invoke-ContentFreeProcess `
        -FileName $pwsh `
        -Arguments @('-NoProfile', '-Command', "[Console]::Out.Write('$caseCanary')") `
        -AllowedStandardOutput @('approved')
} 'process standard output rejected' $caseCanary

$stdoutCanary = 'stdout-canary-not-a-secret'
Assert-RejectedWithoutCanary {
    Invoke-ContentFreeProcess `
        -FileName $pwsh `
        -Arguments @('-NoProfile', '-Command', "[Console]::Out.Write('$stdoutCanary')") `
        -AllowedStandardOutput @('approved')
} 'process standard output rejected' $stdoutCanary

$stderrCanary = 'stderr-canary-not-a-secret'
Assert-RejectedWithoutCanary {
    Invoke-ContentFreeProcess `
        -FileName $pwsh `
        -Arguments @('-NoProfile', '-Command', "[Console]::Error.Write('$stderrCanary')") `
        -AllowedStandardOutput @('')
} 'process standard error rejected' $stderrCanary

$stdinCanary = 'stdin-canary-not-a-secret'
Assert-RejectedWithoutCanary {
    Invoke-ContentFreeProcess `
        -FileName $pwsh `
        -Arguments @('-NoProfile', '-Command', '$value = [Console]::In.ReadToEnd(); [Console]::Out.Write($value)') `
        -InputText $stdinCanary `
        -AllowedStandardOutput @('approved')
} 'process standard output rejected' $stdinCanary

$captured = Invoke-ContentFreeProcess `
    -FileName $pwsh `
    -Arguments @('-NoProfile', '-Command', '[Console]::Out.Write(''opaque-value'')') `
    -AllowedStandardOutputPattern '^opaque-value$' `
    -CaptureStandardOutputAs 'opaque'
Assert-True ($captured.Status -ceq 'matched') 'allowlisted capture did not succeed'
$compared = Invoke-ContentFreeProcess `
    -FileName $pwsh `
    -Arguments @('-NoProfile', '-Command', '[Console]::Out.Write(''opaque-value'')') `
    -StandardOutputMustEqualCapture 'opaque'
Assert-True ($compared.Status -ceq 'matched') 'opaque output comparison did not succeed'
Clear-ContentFreeProcessCapture -Name 'opaque'

$outputBoundFailure = $null
try {
    Invoke-ContentFreeProcess `
        -FileName $pwsh `
        -Arguments @('-NoProfile', '-Command', '[Console]::Out.Write(("x" * 4096)); Start-Sleep -Seconds 30') `
        -AllowedStandardOutput @('') `
        -MaximumOutputBytes 1024 `
        -TimeoutMilliseconds 5000 | Out-Null
} catch {
    $outputBoundFailure = $_.Exception.Message
}
Assert-True ($outputBoundFailure -ceq 'process output exceeded bound') 'process output was not terminated at the configured bound'

$stderrBoundFailure = $null
try {
    Invoke-ContentFreeProcess `
        -FileName $pwsh `
        -Arguments @('-NoProfile', '-Command', '[Console]::Error.Write(("x" * 4096)); Start-Sleep -Seconds 30') `
        -AllowedStandardOutput @('') `
        -MaximumOutputBytes 1024 `
        -TimeoutMilliseconds 5000 | Out-Null
} catch {
    $stderrBoundFailure = $_.Exception.Message
}
Assert-True ($stderrBoundFailure -ceq 'process output exceeded bound') 'stderr output was not terminated at the configured bound'

$unpublished = ConvertTo-ContentFreeSafeValue -Kind 'PortBindings' -Output '{}'
Assert-True (-not $unpublished) 'empty port bindings were not recognized as unpublished'
$published = ConvertTo-ContentFreeSafeValue -Kind 'PortBindings' -Output '{"443/tcp":[{"HostIp":"127.0.0.1","HostPort":"8443"}]}'
Assert-True $published 'exact loopback proxy publication was not recognized'

$serviceList = [System.Collections.Generic.List[string]]::new()
[void]$serviceList.Add('mock')
[void]$serviceList.Add('app')
$services = @(ConvertTo-LocalDemoServiceArray -Services $serviceList)
Assert-True ($services.Count -eq 2) 'generic service list was not flattened'
Assert-True ($services[0] -is [string] -and $services[1] -is [string]) 'flattened service list contains a non-string value'
Assert-True (($services -join ',') -ceq 'mock,app') 'flattened service list changed service order'

$invalidServiceRejected = $false
try {
    ConvertTo-LocalDemoServiceArray -Services @('mock', 'db') | Out-Null
} catch {
    $invalidServiceRejected = $_.Exception.Message -ceq 'service list rejected'
}
Assert-True $invalidServiceRejected 'service list accepted a database recreation'

$recoveryStatuses = @(
    'RECOVERY_PASS',
    'RECOVERY_FAILED_PREFLIGHT_RETAINED_BACKUP_NO_MUTATION',
    'RECOVERY_FAILED_ROTATION_DATABASE_ROLLED_BACK',
    'RECOVERY_FAILED_POST_VERIFY_UPSTREAM_TLS_ROLLBACK_RUNTIME_BOUNDARY_FAILED'
)
foreach ($status in $recoveryStatuses) {
    $safeStatus = ConvertTo-ContentFreeSafeValue -Kind 'RecoveryStatus' -Output $status
    Assert-True ($safeStatus -ceq $status) 'fixed recovery status was not accepted'
}

$verificationStatuses = @(
    'RECOVERY_VERIFY_RECOVERED_PASS',
    'RECOVERY_VERIFY_ROLLED_BACK_PASS',
    'RECOVERY_VERIFY_RECOVERED_FAILED_VERIFY_DATABASE_AUTH'
)
foreach ($status in $verificationStatuses) {
    $safeStatus = ConvertTo-ContentFreeSafeValue -Kind 'RecoveryVerificationStatus' -Output $status
    Assert-True ($safeStatus -ceq $status) 'fixed recovery verification status was not accepted'
}

foreach ($status in @(
    'RECOVERY_FAILED_secret_NO_MUTATION',
    'RECOVERY_VERIFY_RECOVERED_FAILED_secret',
    'RECOVERY_PASS unexpected'
)) {
    $rejected = $false
    try {
        $kind = if ($status.StartsWith('RECOVERY_VERIFY_', [StringComparison]::Ordinal)) {
            'RecoveryVerificationStatus'
        } else {
            'RecoveryStatus'
        }
        ConvertTo-ContentFreeSafeValue -Kind $kind -Output $status | Out-Null
    } catch {
        $rejected = $_.Exception.Message -ceq 'process standard output rejected'
    }
    Assert-True $rejected 'recovery status boundary accepted non-contract output'
}

Write-Host 'Recovery boundary regression tests passed.'
