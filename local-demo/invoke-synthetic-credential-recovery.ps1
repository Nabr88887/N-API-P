param(
    [Parameter(Mandatory)]
    [ValidateSet('Recover', 'VerifyRecovered', 'VerifyRolledBack')]
    [string]$Operation
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'SilentlyContinue'
$callerPhase = 'CALLER_SETUP'

try {
    $scriptRoot = (Resolve-Path $PSScriptRoot).Path
    . (Join-Path $scriptRoot 'recovery-boundary.ps1')
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $docker = (Get-Command docker -ErrorAction Stop).Source

    if ($Operation -ceq 'Recover') {
        $helper = Join-Path $scriptRoot '.runtime/synthetic-credential-rotation.ps1'
        $containerArguments = @(
            'ps',
            '--filter', 'label=com.docker.compose.project=n-api-p-local-demo',
            '--filter', 'label=com.docker.compose.service=db',
            '--filter', 'status=running',
            '--format', '{{.ID}}'
        )
        $callerPhase = 'CALLER_CAPTURE_DATABASE_CONTAINER'
        $result = Invoke-ContentFreeProcess `
            -FileName $docker `
            -Arguments $containerArguments `
            -AllowedStandardOutputPattern '^[0-9a-f]{12,64}$' `
            -SafeOutputKind 'ContainerID'
        $databaseContainerID = [string]$result.SafeValue
        $callerPhase = 'CALLER_CAPTURE_DATABASE_VOLUME'
        $result = Invoke-ContentFreeProcess `
            -FileName $docker `
            -Arguments @('inspect', '--format', '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}', $databaseContainerID) `
            -AllowedStandardOutputPattern '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' `
            -SafeOutputKind 'VolumeID'
        $databaseVolumeID = [string]$result.SafeValue

        if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
            throw 'recovery target missing'
        }
        $helperItem = Get-Item -LiteralPath $helper -Force
        if ($helperItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'recovery target boundary drift'
        }
        $callerPhase = 'CALLER_EXECUTE_RECOVERY'
        $result = Invoke-ContentFreeProcess `
            -FileName $pwsh `
            -Arguments @('-NoProfile', '-File', $helper) `
            -ExitCodeMode 'any' `
            -AllowedStandardOutputPattern (Get-ContentFreeRecoveryStatusPattern) `
            -SafeOutputKind 'RecoveryStatus' `
            -MaximumOutputBytes 512 `
            -TimeoutMilliseconds 600000
        $recoveryStatus = [string]$result.SafeValue
        $recoveryExitCode = $result.ExitCode
        $recoveryPassed = $recoveryStatus -ceq 'RECOVERY_PASS'
        if (($recoveryPassed -and $recoveryExitCode -ne 0) -or (-not $recoveryPassed -and $recoveryExitCode -eq 0)) {
            throw 'result and exit status disagree'
        }
        Write-Output $result.SafeValue

        if ($recoveryStatus.EndsWith('_NO_MUTATION', [StringComparison]::Ordinal)) {
            exit 1
        }
        $expectedState = if ($recoveryPassed) { 'Recovered' } else { 'RolledBack' }
        $target = Join-Path $scriptRoot 'synthetic-recovery-readonly-verifier.ps1'
        $callerPhase = 'CALLER_EXECUTE_VERIFICATION'
        $result = Invoke-ContentFreeProcess `
            -FileName $pwsh `
            -Arguments @(
                '-NoProfile', '-File', $target,
                '-ExpectedState', $expectedState,
                '-ExpectedDatabaseContainerID', $databaseContainerID,
                '-ExpectedDatabaseVolumeID', $databaseVolumeID
        ) `
            -ExitCodeMode 'any' `
            -AllowedStandardOutputPattern (Get-ContentFreeRecoveryVerificationStatusPattern) `
            -SafeOutputKind 'RecoveryVerificationStatus' `
            -MaximumOutputBytes 512 `
            -TimeoutMilliseconds 180000
        $verificationStateToken = if ($expectedState -ceq 'RolledBack') {
            'ROLLED_BACK'
        } else {
            'RECOVERED'
        }
        $verificationPassed = $result.SafeValue -ceq "RECOVERY_VERIFY_${verificationStateToken}_PASS"
        if (($verificationPassed -and $result.ExitCode -ne 0) -or (-not $verificationPassed -and $result.ExitCode -eq 0)) {
            throw 'result and exit status disagree'
        }
        Write-Output $result.SafeValue
        if ($recoveryPassed -and $verificationPassed) {
            $cleanupPhase = 'CLEANUP_BACKUP'
            try {
                $runtime = Join-Path $scriptRoot '.runtime'
                $candidates = @(Get-ChildItem -LiteralPath $runtime -Directory -Force | Where-Object {
                    $_.Name -match '^rotation-backup-[0-9a-f]{32}$'
                })
                if ($candidates.Count -ne 1 -or ($candidates[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw 'cleanup backup boundary drift'
                }
                $backupRoot = $candidates[0].FullName
                Remove-Item -LiteralPath $backupRoot -Recurse -Force

                $cleanupPhase = 'CLEANUP_HELPER'
                Remove-Item -LiteralPath $helper -Force

                $cleanupPhase = 'CLEANUP_VERIFY'
                $remainingBackups = @(Get-ChildItem -LiteralPath $runtime -Directory -Force | Where-Object {
                    $_.Name -match '^rotation-backup-[0-9a-f]{32}$'
                })
                if ($remainingBackups.Count -ne 0 -or (Test-Path -LiteralPath $helper)) {
                    throw 'cleanup verification failed'
                }
                Write-Output 'RECOVERY_CLEANUP_PASS'
                exit 0
            } catch {
                Write-Output ('RECOVERY_CLEANUP_FAILED_{0}' -f $cleanupPhase)
                exit 1
            }
        }
        exit 1
    } else {
        throw 'standalone verification is not supported'
    }
} catch {
    Write-Output ('RECOVERY_CALLER_FAILED_{0}' -f $callerPhase)
    exit 1
}
