$ErrorActionPreference = 'Stop'

$lifecycle = Join-Path $PSScriptRoot 'certificate-lifecycle.ps1'
if (-not (Test-Path -LiteralPath $lifecycle)) {
    throw 'certificate lifecycle implementation is missing'
}
. $lifecycle

$openssl = (Get-Command openssl -ErrorAction Stop).Source
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('n-api-p-certificate-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) {
        throw $message
    }
}

function Get-FileDigest([string]$path) {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function New-TestCertificate(
    [string]$name,
    [string]$commonName,
    [string]$subjectAlternativeName,
    [int]$validDays
) {
    $config = Join-Path $testRoot "$name.cnf"
    $certificate = Join-Path $testRoot "$name.crt"
    $key = Join-Path $testRoot "$name.key"
    [IO.File]::WriteAllText(
        $config,
        "[req]`ndistinguished_name=req_dn`nx509_extensions=v3_req`n[req_dn]`n[v3_req]`nsubjectAltName=$subjectAlternativeName`nbasicConstraints=critical,CA:TRUE`n",
        [Text.UTF8Encoding]::new($false)
    )
    & $openssl req -x509 -newkey rsa:2048 -nodes -days $validDays -subj "/CN=$commonName" -keyout $key -out $certificate -config $config -extensions v3_req 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "generate test certificate $name failed"
    }
    return @{ Certificate = $certificate; Key = $key; Config = $config }
}

try {
    $nearExpiry = New-TestCertificate 'near-expiry' 'localhost' 'DNS:localhost,IP:127.0.0.1' 1
    $nearExpiryDigest = Get-FileDigest $nearExpiry.Certificate
    $nearExpiryChanged = Update-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $nearExpiry.Certificate -KeyPath $nearExpiry.Key -ConfigPath $nearExpiry.Config -CommonName 'localhost' -ExpectedHost 'localhost'
    Assert-True $nearExpiryChanged 'a certificate inside the renewal window was not renewed'
    Assert-True ((Get-FileDigest $nearExpiry.Certificate) -ne $nearExpiryDigest) 'renewal did not replace the near-expiry certificate'

    Assert-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $nearExpiry.Certificate -KeyPath $nearExpiry.Key -ExpectedHost 'localhost' -MinimumRemainingSeconds 86400

    $healthy = New-TestCertificate 'healthy' 'localhost' 'DNS:localhost,IP:127.0.0.1' 2
    $healthyCertificateDigest = Get-FileDigest $healthy.Certificate
    $healthyKeyDigest = Get-FileDigest $healthy.Key
    $healthyChanged = Update-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $healthy.Certificate -KeyPath $healthy.Key -ConfigPath $healthy.Config -CommonName 'localhost' -ExpectedHost 'localhost'
    Assert-True (-not $healthyChanged) 'a healthy certificate was rotated unnecessarily'
    Assert-True ((Get-FileDigest $healthy.Certificate) -eq $healthyCertificateDigest) 'the healthy certificate changed'
    Assert-True ((Get-FileDigest $healthy.Key) -eq $healthyKeyDigest) 'the healthy private key changed'

    $renewalCandidate = New-TestCertificate 'renewal-candidate' 'localhost' 'DNS:localhost,IP:127.0.0.1' 1
    Assert-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $renewalCandidate.Certificate -KeyPath $renewalCandidate.Key -ExpectedHost 'localhost' -MinimumRemainingSeconds 86400 -AllowExpired

    $mismatched = New-TestCertificate 'mismatched' 'demo-newapi' 'DNS:demo-newapi' 2
    $other = New-TestCertificate 'other' 'demo-newapi' 'DNS:demo-newapi' 2
    Copy-Item -LiteralPath $other.Key -Destination $mismatched.Key -Force
    $mismatchedKeyDigest = Get-FileDigest $mismatched.Key
    $mismatchedChanged = Update-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $mismatched.Certificate -KeyPath $mismatched.Key -ConfigPath $mismatched.Config -CommonName 'demo-newapi' -ExpectedHost 'demo-newapi'
    Assert-True $mismatchedChanged 'a mismatched certificate and key were not renewed'
    Assert-True ((Get-FileDigest $mismatched.Key) -ne $mismatchedKeyDigest) 'renewal did not replace the mismatched private key'
    Assert-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $mismatched.Certificate -KeyPath $mismatched.Key -ExpectedHost 'demo-newapi' -MinimumRemainingSeconds 86400

    $rollback = New-TestCertificate 'rollback' 'demo-newapi' 'DNS:demo-newapi' 2
    Copy-Item -LiteralPath $other.Key -Destination $rollback.Key -Force
    $rollbackCertificateDigest = Get-FileDigest $rollback.Certificate
    $rollbackKeyDigest = Get-FileDigest $rollback.Key
    $invalidConfig = Join-Path $testRoot 'invalid-candidate.cnf'
    [IO.File]::WriteAllText($invalidConfig, "[req]`ndistinguished_name=req_dn`nx509_extensions=v3_req`n[req_dn]`n[v3_req]`nsubjectAltName=DNS:wrong-host`n", [Text.UTF8Encoding]::new($false))
    $candidateRejected = $false
    try {
        Update-LocalDemoCertificate -OpenSSL $openssl -CertificatePath $rollback.Certificate -KeyPath $rollback.Key -ConfigPath $invalidConfig -CommonName 'demo-newapi' -ExpectedHost 'demo-newapi' | Out-Null
    } catch {
        $candidateRejected = $true
    }
    Assert-True $candidateRejected 'an invalid replacement candidate was accepted'
    Assert-True ((Get-FileDigest $rollback.Certificate) -eq $rollbackCertificateDigest) 'candidate validation failure changed the active certificate'
    Assert-True ((Get-FileDigest $rollback.Key) -eq $rollbackKeyDigest) 'candidate validation failure changed the active private key'

    $trustCarrier = Join-Path $testRoot 'ca-certificates.crt'
    [IO.File]::WriteAllText($trustCarrier, 'stale', [Text.UTF8Encoding]::new($false))
    $trustChanged = Sync-LocalDemoTrustCarrier -CertificatePath $mismatched.Certificate -TrustCarrierPath $trustCarrier
    Assert-True $trustChanged 'a stale mock trust carrier was not updated'
    Assert-True ((Get-FileDigest $trustCarrier) -eq (Get-FileDigest $mismatched.Certificate)) 'the mock trust carrier does not match the active mock certificate'
    Assert-True (-not (Sync-LocalDemoTrustCarrier -CertificatePath $mismatched.Certificate -TrustCarrierPath $trustCarrier)) 'an unchanged trust carrier was rewritten'

    Assert-True (((Get-LocalDemoAffectedServices $true $false $false) -join ',') -eq 'proxy') 'portal renewal selected unexpected services'
    Assert-True (((Get-LocalDemoAffectedServices $false $false $true) -join ',') -eq 'app,proxy') 'trust renewal selected unexpected services'
    Assert-True (((Get-LocalDemoAffectedServices $true $true $true) -join ',') -eq 'mock,app,proxy') 'mock renewal selected unexpected services'
    Assert-True (@(Get-LocalDemoAffectedServices $false $false $false).Count -eq 0) 'healthy certificates selected services for recreation'

    Write-Host 'Certificate lifecycle regression tests passed.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
