$script:LocalDemoCertificateValidityDays = 2
$script:LocalDemoCertificateRenewalWindowSeconds = 86400

function Test-LocalDemoByteEquality([byte[]]$left, [byte[]]$right) {
    if ($left.Length -ne $right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $left.Length; $index++) {
        if ($left[$index] -ne $right[$index]) {
            return $false
        }
    }
    return $true
}

function Assert-LocalDemoCertificate(
    [string]$OpenSSL,
    [string]$CertificatePath,
    [string]$KeyPath,
    [string]$ExpectedHost,
    [int]$MinimumRemainingSeconds,
    [switch]$AllowExpired
) {
    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf) -or -not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
        throw "certificate pair for $ExpectedHost is incomplete"
    }

    if (-not $AllowExpired) {
        & $OpenSSL x509 -in $CertificatePath -noout -checkend $MinimumRemainingSeconds 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "certificate for $ExpectedHost is expired, malformed, or inside the renewal window"
        }
    }
    & $OpenSSL x509 -in $CertificatePath -noout -checkhost $ExpectedHost 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "certificate does not match $ExpectedHost"
    }
    $verifyArguments = @('verify')
    if ($AllowExpired) {
        $verifyArguments += '-no_check_time'
    }
    $verifyArguments += @('-CAfile', $CertificatePath, '-verify_hostname', $ExpectedHost, $CertificatePath)
    & $OpenSSL @verifyArguments 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "certificate chain or current validity check failed for $ExpectedHost"
    }
    & $OpenSSL pkey -in $KeyPath -check -noout 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "private key validation failed for $ExpectedHost"
    }

    $certificatePublicKey = @(& $OpenSSL x509 -in $CertificatePath -pubkey -noout 2>$null)
    if ($LASTEXITCODE -ne 0 -or $certificatePublicKey.Count -eq 0) {
        throw "certificate public key extraction failed for $ExpectedHost"
    }
    $privatePublicKey = @(& $OpenSSL pkey -in $KeyPath -pubout 2>$null)
    if ($LASTEXITCODE -ne 0 -or $privatePublicKey.Count -eq 0) {
        throw "private public key extraction failed for $ExpectedHost"
    }
    if (($certificatePublicKey -join "`n") -cne ($privatePublicKey -join "`n")) {
        throw "certificate and private key do not match for $ExpectedHost"
    }
}

function Install-LocalDemoCertificatePair(
    [string]$OpenSSL,
    [string]$CertificatePath,
    [string]$KeyPath,
    [string]$StagedCertificatePath,
    [string]$StagedKeyPath,
    [string]$ExpectedHost,
    [int]$MinimumRemainingSeconds
) {
    $transactionID = [Guid]::NewGuid().ToString('N')
    $certificateBackup = "$CertificatePath.backup.$transactionID"
    $keyBackup = "$KeyPath.backup.$transactionID"
    $certificateBackedUp = $false
    $keyBackedUp = $false
    $certificateInstalled = $false
    $keyInstalled = $false

    try {
        if (Test-Path -LiteralPath $CertificatePath) {
            Move-Item -LiteralPath $CertificatePath -Destination $certificateBackup
            $certificateBackedUp = $true
        }
        if (Test-Path -LiteralPath $KeyPath) {
            Move-Item -LiteralPath $KeyPath -Destination $keyBackup
            $keyBackedUp = $true
        }
        Move-Item -LiteralPath $StagedCertificatePath -Destination $CertificatePath
        $certificateInstalled = $true
        Move-Item -LiteralPath $StagedKeyPath -Destination $KeyPath
        $keyInstalled = $true
        Assert-LocalDemoCertificate -OpenSSL $OpenSSL -CertificatePath $CertificatePath -KeyPath $KeyPath -ExpectedHost $ExpectedHost -MinimumRemainingSeconds $MinimumRemainingSeconds
    } catch {
        if ($certificateInstalled) {
            Remove-Item -LiteralPath $CertificatePath -Force -ErrorAction SilentlyContinue
        }
        if ($keyInstalled) {
            Remove-Item -LiteralPath $KeyPath -Force -ErrorAction SilentlyContinue
        }
        if ($certificateBackedUp) {
            Move-Item -LiteralPath $certificateBackup -Destination $CertificatePath -Force
        }
        if ($keyBackedUp) {
            Move-Item -LiteralPath $keyBackup -Destination $KeyPath -Force
        }
        throw
    }

    if ($certificateBackedUp) {
        Remove-Item -LiteralPath $certificateBackup -Force
    }
    if ($keyBackedUp) {
        Remove-Item -LiteralPath $keyBackup -Force
    }
}

function Update-LocalDemoCertificate(
    [string]$OpenSSL,
    [string]$CertificatePath,
    [string]$KeyPath,
    [string]$ConfigPath,
    [string]$CommonName,
    [string]$ExpectedHost
) {
    try {
        Assert-LocalDemoCertificate -OpenSSL $OpenSSL -CertificatePath $CertificatePath -KeyPath $KeyPath -ExpectedHost $ExpectedHost -MinimumRemainingSeconds $script:LocalDemoCertificateRenewalWindowSeconds
        return $false
    } catch {
        # Renewal is intentionally silent so callers can enforce a content-free output boundary.
    }

    $transactionID = [Guid]::NewGuid().ToString('N')
    $stagedCertificate = "$CertificatePath.new.$transactionID"
    $stagedKey = "$KeyPath.new.$transactionID"
    try {
        & $OpenSSL req -x509 -newkey rsa:2048 -nodes -days $script:LocalDemoCertificateValidityDays -subj "/CN=$CommonName" -keyout $stagedKey -out $stagedCertificate -config $ConfigPath -extensions v3_req 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "generate certificate for $ExpectedHost failed with exit code $LASTEXITCODE"
        }
        Assert-LocalDemoCertificate -OpenSSL $OpenSSL -CertificatePath $stagedCertificate -KeyPath $stagedKey -ExpectedHost $ExpectedHost -MinimumRemainingSeconds $script:LocalDemoCertificateRenewalWindowSeconds
        Install-LocalDemoCertificatePair -OpenSSL $OpenSSL -CertificatePath $CertificatePath -KeyPath $KeyPath -StagedCertificatePath $stagedCertificate -StagedKeyPath $stagedKey -ExpectedHost $ExpectedHost -MinimumRemainingSeconds $script:LocalDemoCertificateRenewalWindowSeconds
        return $true
    } finally {
        Remove-Item -LiteralPath $stagedCertificate, $stagedKey -Force -ErrorAction SilentlyContinue
    }
}

function Get-LocalDemoAffectedServices(
    [bool]$PortalRenewed,
    [bool]$MockRenewed,
    [bool]$TrustChanged
) {
    if ($MockRenewed) {
        return @('mock', 'app', 'proxy')
    }
    if ($TrustChanged) {
        return @('app', 'proxy')
    }
    if ($PortalRenewed) {
        return @('proxy')
    }
    return @()
}

function Assert-LocalDemoPortalTLS(
    [string]$OpenSSL,
    [string]$CertificatePath,
    [string]$Path
) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $OpenSSL
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
        's_client', '-connect', '127.0.0.1:8443', '-servername', 'localhost',
        '-CAfile', $CertificatePath, '-verify_hostname', 'localhost',
        '-verify_return_error', '-quiet', '-ign_eof'
    )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "portal TLS probe could not start for $Path"
    }
    try {
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write("GET $Path HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n")
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill($true)
            throw "portal TLS probe timed out for $Path"
        }
        $response = $standardOutput.GetAwaiter().GetResult()
        $null = $standardError.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $response -notmatch '(?m)^HTTP/1\.[01] 200(?: |$)') {
            throw "verified portal TLS probe failed for $Path"
        }
    } finally {
        $process.Dispose()
    }
}

function Sync-LocalDemoTrustCarrier([string]$CertificatePath, [string]$TrustCarrierPath) {
    $certificateBytes = [IO.File]::ReadAllBytes($CertificatePath)
    if ($certificateBytes.Length -eq 0) {
        throw 'active mock certificate is empty'
    }
    if (Test-Path -LiteralPath $TrustCarrierPath -PathType Leaf) {
        $trustBytes = [IO.File]::ReadAllBytes($TrustCarrierPath)
        if (Test-LocalDemoByteEquality $certificateBytes $trustBytes) {
            return $false
        }
    }

    $transactionID = [Guid]::NewGuid().ToString('N')
    $stagedTrustCarrier = "$TrustCarrierPath.new.$transactionID"
    $backupTrustCarrier = "$TrustCarrierPath.backup.$transactionID"
    $backedUp = $false
    $installed = $false
    try {
        [IO.File]::WriteAllBytes($stagedTrustCarrier, $certificateBytes)
        if (Test-Path -LiteralPath $TrustCarrierPath) {
            Move-Item -LiteralPath $TrustCarrierPath -Destination $backupTrustCarrier
            $backedUp = $true
        }
        Move-Item -LiteralPath $stagedTrustCarrier -Destination $TrustCarrierPath
        $installed = $true
        if (-not (Test-LocalDemoByteEquality $certificateBytes ([IO.File]::ReadAllBytes($TrustCarrierPath)))) {
            throw 'mock trust carrier validation failed after replacement'
        }
    } catch {
        if ($installed) {
            Remove-Item -LiteralPath $TrustCarrierPath -Force -ErrorAction SilentlyContinue
        }
        if ($backedUp) {
            Move-Item -LiteralPath $backupTrustCarrier -Destination $TrustCarrierPath -Force
        }
        throw
    } finally {
        Remove-Item -LiteralPath $stagedTrustCarrier -Force -ErrorAction SilentlyContinue
    }
    if ($backedUp) {
        Remove-Item -LiteralPath $backupTrustCarrier -Force
    }
    return $true
}
