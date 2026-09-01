$script:ContentFreeProcessCaptures = @{}

function ConvertTo-LocalDemoServiceArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Services
    )

    $flattened = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Services)) {
        if ($item -is [System.Collections.IEnumerable] -and $item -isnot [string]) {
            foreach ($nested in $item) {
                [void]$flattened.Add([string]$nested)
            }
        } else {
            [void]$flattened.Add([string]$item)
        }
    }

    foreach ($service in $flattened) {
        if ($service -cnotin @('mock', 'app', 'proxy')) {
            throw 'service list rejected'
        }
    }
    return [string[]]$flattened.ToArray()
}

function Test-ContentFreeOutputPattern {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Output,
        [string[]]$AllowedStandardOutput,
        [string]$AllowedStandardOutputPattern,
        [string]$StandardOutputMustEqualCapture
    )

    $normalized = $Output.Trim()
    if (-not [string]::IsNullOrEmpty($StandardOutputMustEqualCapture)) {
        if (-not $script:ContentFreeProcessCaptures.ContainsKey($StandardOutputMustEqualCapture) -or
            $normalized -cne $script:ContentFreeProcessCaptures[$StandardOutputMustEqualCapture]) {
            return $false
        }
    }
    if ($null -ne $AllowedStandardOutput -and -not (@($AllowedStandardOutput) -ccontains $normalized)) {
        return $false
    }
    if (-not [string]::IsNullOrEmpty($AllowedStandardOutputPattern) -and $normalized -cnotmatch $AllowedStandardOutputPattern) {
        return $false
    }
    if ([string]::IsNullOrEmpty($StandardOutputMustEqualCapture) -and $null -eq $AllowedStandardOutput -and [string]::IsNullOrEmpty($AllowedStandardOutputPattern)) {
        return [string]::IsNullOrEmpty($normalized)
    }
    return $true
}

function Test-ContentFreeErrorPattern {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ErrorOutput,
        [string[]]$AllowedStandardError,
        [string[]]$AllowedStandardErrorPattern
    )

    $normalized = $ErrorOutput.Trim()
    if ($null -ne $AllowedStandardError -and @($AllowedStandardError) -ccontains $normalized) {
        return $true
    }
    if ($null -ne $AllowedStandardErrorPattern) {
        foreach ($pattern in $AllowedStandardErrorPattern) {
            if ($normalized -cmatch $pattern) {
                return $true
            }
        }
        return $false
    }
    if ($null -eq $AllowedStandardError) {
        return [string]::IsNullOrEmpty($normalized)
    }
    return $false
}

function Stop-ContentFreeProcess {
    param(
        [Parameter(Mandatory)]
        [Diagnostics.Process]$Process
    )

    try {
        if (-not $Process.HasExited) {
            $Process.Kill($true)
        }
    } catch {
        # The child may have exited between the state check and Kill().
    }
}

function Get-ContentFreeRecoveryStatusPattern {
    $primary = '(?:POST_VERIFY_DATABASE_AUTH|POST_VERIFY_RUNTIME|POST_VERIFY_UPSTREAM_TLS|PREFLIGHT_DATABASE_AUTH|PREFLIGHT_RETAINED_BACKUP|PREFLIGHT_RUNTIME_ENV|PREFLIGHT_SERVICE_BOUNDARY|PREFLIGHT_SOURCE_BOUNDARY|ROTATION_CERTIFICATES|ROTATION_DATABASE|ROTATION_RUNTIME_ENV|SERVICE_RECREATE)'
    $rollback = '(?:ROLLBACK_CERTIFICATES|ROLLBACK_DATABASE|ROLLBACK_DATABASE_AUTH|ROLLBACK_RUNTIME_BOUNDARY|ROLLBACK_RUNTIME_ENV|ROLLBACK_SERVICES)'
    return "^(?:RECOVERY_PASS|RECOVERY_FAILED_${primary}_(?:NO_MUTATION|ROLLED_BACK)|RECOVERY_FAILED_${primary}_${rollback}_FAILED)$"
}

function Get-ContentFreeRecoveryVerificationStatusPattern {
    $phase = '(?:VERIFY_DATABASE_AUTH|VERIFY_RETAINED_BACKUP|VERIFY_ROLLBACK_FILES|VERIFY_RUNTIME_ENV|VERIFY_SERVICE_BOUNDARY|VERIFY_SETUP|VERIFY_SOURCE_BOUNDARY|VERIFY_TLS|VERIFY_UPSTREAM_TLS)'
    return "^RECOVERY_VERIFY_(?:RECOVERED|ROLLED_BACK)_(?:PASS|FAILED_${phase})$"
}

function ConvertTo-ContentFreeSafeValue {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ContainerID', 'ImageID', 'Revision', 'Status', 'VolumeID', 'Configured', 'PortBindings', 'Http200', 'RecoveryStatus', 'RecoveryVerificationStatus', 'RecoveryProbeClassification', 'HttpStatusCode')]
        [string]$Kind,
        [Parameter(Mandatory)]
        [string]$Output
    )

    $normalized = $Output.Trim()
    switch ($Kind) {
        'ContainerID' {
            if ($normalized -cnotmatch '^[0-9a-f]{12,64}$') { throw 'process standard output rejected' }
            return $normalized
        }
        'ImageID' {
            if ($normalized -cnotmatch '^sha256:[0-9a-f]{64}$') { throw 'process standard output rejected' }
            return $normalized
        }
        'Revision' {
            if ($normalized -cnotmatch '^[0-9a-f]{40}$') { throw 'process standard output rejected' }
            return $normalized
        }
        'Status' {
            if ($normalized -cnotin @('created', 'dead', 'exited', 'healthy', 'paused', 'restarting', 'running', 'unhealthy')) {
                throw 'process standard output rejected'
            }
            return $normalized
        }
        'VolumeID' {
            if ($normalized -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$') { throw 'process standard output rejected' }
            return $normalized
        }
        'Configured' {
            if ($normalized -cne 'configured') { throw 'process standard output rejected' }
            return $true
        }
        'PortBindings' {
            if ($normalized -in @('', '<no value>', 'null', '{}')) {
                return $false
            }
            try {
                $bindings = $normalized | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw 'process standard output rejected'
            }
            $properties = @($bindings.PSObject.Properties.Name)
            if ($properties.Count -ne 1 -or $properties[0] -cne '443/tcp') {
                throw 'process standard output rejected'
            }
            $entries = @($bindings.'443/tcp')
            if ($entries.Count -ne 1 -or
                [string]$entries[0].HostIp -cne '127.0.0.1' -or
                [string]$entries[0].HostPort -cne '8443') {
                throw 'process standard output rejected'
            }
            return $true
        }
        'Http200' {
            if ($normalized -cnotmatch '(?m)^HTTP/1\.[01] 200(?: |$)') { throw 'process standard output rejected' }
            return $true
        }
        'RecoveryStatus' {
            if ($normalized -cnotmatch (Get-ContentFreeRecoveryStatusPattern)) { throw 'process standard output rejected' }
            return $normalized
        }
        'RecoveryVerificationStatus' {
            if ($normalized -cnotmatch (Get-ContentFreeRecoveryVerificationStatusPattern)) { throw 'process standard output rejected' }
            return $normalized
        }
        'RecoveryProbeClassification' {
            if ($normalized -cnotin @('tls_http_404', 'tls_error', 'http_other', 'tls_timeout')) { throw 'process standard output rejected' }
            return $normalized
        }
        'HttpStatusCode' {
            if ($normalized -cnotmatch '^[0-9]{3}$') { throw 'process standard output rejected' }
            return $normalized
        }
    }
}

function Invoke-ContentFreeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FileName,
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [string]$InputText,
        [ValidateSet('zero', 'nonzero', 'any')]
        [string]$ExitCodeMode = 'zero',
        [string[]]$AllowedStandardOutput,
        [string]$AllowedStandardOutputPattern,
        [string[]]$AllowedStandardError,
        [string[]]$AllowedStandardErrorPattern,
        [ValidateSet('ContainerID', 'ImageID', 'Revision', 'Status', 'VolumeID', 'Configured', 'PortBindings', 'Http200', 'RecoveryStatus', 'RecoveryVerificationStatus', 'RecoveryProbeClassification', 'HttpStatusCode')]
        [string]$SafeOutputKind,
        [string]$CaptureStandardOutputAs,
        [string]$StandardOutputMustEqualCapture,
        [int]$MaximumOutputBytes = 65536,
        [ValidateRange(1, 600000)]
        [int]$TimeoutMilliseconds = 30000
    )

    if ($MaximumOutputBytes -lt 1) {
        throw 'invalid process output bound'
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    try {
        if (-not $process.Start()) {
            throw 'process start failed'
        }
        $started = $true
        if ($null -ne $InputText) {
            $process.StandardInput.Write($InputText)
        }
        $process.StandardInput.Close()

        # Consume both redirected streams in bounded chunks so a noisy child
        # cannot fill an unbounded ReadToEndAsync buffer before validation.
        $stdoutReader = $process.StandardOutput
        $stderrReader = $process.StandardError
        $stdoutChars = [char[]]::new(4096)
        $stderrChars = [char[]]::new(4096)
        $stdoutBuilder = [Text.StringBuilder]::new()
        $stderrBuilder = [Text.StringBuilder]::new()
        $stdoutBytes = 0
        $stderrBytes = 0
        $stdoutDone = $false
        $stderrDone = $false
        $stdoutTask = $stdoutReader.ReadAsync($stdoutChars, 0, $stdoutChars.Length)
        $stderrTask = $stderrReader.ReadAsync($stderrChars, 0, $stderrChars.Length)
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        while (-not ($stdoutDone -and $stderrDone)) {
            $pending = [System.Collections.Generic.List[Threading.Tasks.Task]]::new()
            if (-not $stdoutDone) { [void]$pending.Add($stdoutTask) }
            if (-not $stderrDone) { [void]$pending.Add($stderrTask) }
            $remaining = $TimeoutMilliseconds - [int]$stopwatch.ElapsedMilliseconds
            if ($remaining -le 0) {
                Stop-ContentFreeProcess -Process $process
                throw 'process timeout'
            }
            $completedTask = [Threading.Tasks.Task]::WhenAny($pending.ToArray())
            if (-not $completedTask.Wait($remaining)) {
                Stop-ContentFreeProcess -Process $process
                throw 'process timeout'
            }
            $completed = $completedTask.Result
            if (-not $stdoutDone -and $completed -eq $stdoutTask) {
                $count = $stdoutTask.GetAwaiter().GetResult()
                if ($count -eq 0) {
                    $stdoutDone = $true
                } else {
                    $chunk = [string]::new($stdoutChars, 0, $count)
                    $chunkBytes = [Text.Encoding]::UTF8.GetByteCount($chunk)
                    if ($stdoutBytes -gt $MaximumOutputBytes - $chunkBytes) {
                        Stop-ContentFreeProcess -Process $process
                        throw 'process output exceeded bound'
                    }
                    $stdoutBytes += $chunkBytes
                    [void]$stdoutBuilder.Append($chunk)
                    $stdoutTask = $stdoutReader.ReadAsync($stdoutChars, 0, $stdoutChars.Length)
                }
            } elseif (-not $stderrDone -and $completed -eq $stderrTask) {
                $count = $stderrTask.GetAwaiter().GetResult()
                if ($count -eq 0) {
                    $stderrDone = $true
                } else {
                    $chunk = [string]::new($stderrChars, 0, $count)
                    $chunkBytes = [Text.Encoding]::UTF8.GetByteCount($chunk)
                    if ($stderrBytes -gt $MaximumOutputBytes - $chunkBytes) {
                        Stop-ContentFreeProcess -Process $process
                        throw 'process output exceeded bound'
                    }
                    $stderrBytes += $chunkBytes
                    [void]$stderrBuilder.Append($chunk)
                    $stderrTask = $stderrReader.ReadAsync($stderrChars, 0, $stderrChars.Length)
                }
            }
        }
        $remaining = $TimeoutMilliseconds - [int]$stopwatch.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) {
            Stop-ContentFreeProcess -Process $process
            throw 'process timeout'
        }
        $stdout = $stdoutBuilder.ToString()
        $stderr = $stderrBuilder.ToString()

        $exitAccepted = switch ($ExitCodeMode) {
            'zero' { $process.ExitCode -eq 0 }
            'nonzero' { $process.ExitCode -ne 0 }
            'any' { $true }
        }
        if (-not $exitAccepted) {
            throw 'process exit status rejected'
        }
        if (-not (Test-ContentFreeOutputPattern -Output $stdout -AllowedStandardOutput $AllowedStandardOutput -AllowedStandardOutputPattern $AllowedStandardOutputPattern -StandardOutputMustEqualCapture $StandardOutputMustEqualCapture)) {
            throw 'process standard output rejected'
        }
        if (-not (Test-ContentFreeErrorPattern -ErrorOutput $stderr -AllowedStandardError $AllowedStandardError -AllowedStandardErrorPattern $AllowedStandardErrorPattern)) {
            throw 'process standard error rejected'
        }
        if (-not [string]::IsNullOrEmpty($CaptureStandardOutputAs)) {
            if ([string]::IsNullOrEmpty($AllowedStandardOutputPattern) -and $null -eq $AllowedStandardOutput -and [string]::IsNullOrEmpty($StandardOutputMustEqualCapture)) {
                throw 'capture requires an output allowlist'
            }
            $script:ContentFreeProcessCaptures[$CaptureStandardOutputAs] = $stdout.Trim()
        }
        $result = [ordered]@{
            ExitCode = $process.ExitCode
            Status = 'matched'
        }
        if (-not [string]::IsNullOrEmpty($SafeOutputKind)) {
            $result.SafeValue = ConvertTo-ContentFreeSafeValue -Kind $SafeOutputKind -Output $stdout
        }
        return [pscustomobject]$result
    } catch [System.Management.Automation.RuntimeException] {
        throw
    } catch {
        throw 'process execution failed'
    } finally {
        if ($started) {
            Stop-ContentFreeProcess -Process $process
        }
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Clear-ContentFreeProcessCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    [void]$script:ContentFreeProcessCaptures.Remove($Name)
}

function Get-ContentFreeProcessCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    if (-not $script:ContentFreeProcessCaptures.ContainsKey($Name)) {
        throw 'process capture missing'
    }
    return [string]$script:ContentFreeProcessCaptures[$Name]
}
