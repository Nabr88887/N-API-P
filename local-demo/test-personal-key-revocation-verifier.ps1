$ErrorActionPreference = 'Stop'

$verifier = Join-Path $PSScriptRoot 'personal-key-revocation-verifier.ps1'
if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw 'personal-key revocation verifier is missing'
}
. $verifier

function Assert-Throws([scriptblock]$operation, [string]$message) {
    $threw = $false
    try {
        & $operation
    } catch {
        $threw = $true
    }
    if (-not $threw) {
        throw $message
    }
}

$keyID = '10000000-0000-0000-0000-000000000001'
$validResponse = [pscustomobject]@{
    data = @(
        [pscustomobject]@{ id = '10000000-0000-0000-0000-000000000002'; status = 'active'; revoked_at = $null }
        [pscustomobject]@{ id = $keyID; status = 'revoked'; revoked_at = '2026-08-27T08:00:00Z' }
    )
}
$record = Assert-RevokedPersonalKeyListResponse -Response $validResponse -KeyID $keyID
if ($record.id -ne $keyID) {
    throw 'valid revoked personal-key record was not returned'
}

Assert-PersonalKeyRevokeSucceeded -StatusCode 204
Assert-Throws {
    Assert-PersonalKeyRevokeSucceeded -StatusCode 200
} 'a non-204 revoke response was accepted'

Assert-Throws {
    Assert-RevokedPersonalKeyListResponse -Response ([pscustomobject]@{ data = @() }) -KeyID $keyID
} 'a missing revoked personal-key record was accepted'

Assert-Throws {
    Assert-RevokedPersonalKeyListResponse -Response ([pscustomobject]@{ data = @([pscustomobject]@{ id = $keyID; status = 'active'; revoked_at = $null }) }) -KeyID $keyID
} 'an active personal-key record was accepted as revoked'

Assert-Throws {
    Assert-RevokedPersonalKeyListResponse -Response ([pscustomobject]@{ data = @([pscustomobject]@{ id = $keyID; status = 'revoked'; revoked_at = $null }) }) -KeyID $keyID
} 'a revoked personal-key record without revoked_at was accepted'

Assert-Throws {
    Assert-RevokedPersonalKeyListResponse -Response ([pscustomobject]@{ data = @([pscustomobject]@{ id = $keyID; status = 'revoked'; revoked_at = 'not-a-timestamp' }) }) -KeyID $keyID
} 'a revoked personal-key record with an invalid revoked_at was accepted'

Assert-Throws {
    Assert-RevokedPersonalKeyListResponse -Response ([pscustomobject]@{ data = @(
        [pscustomobject]@{ id = $keyID; status = 'revoked'; revoked_at = '2026-08-27T08:00:00Z' }
        [pscustomobject]@{ id = $keyID; status = 'revoked'; revoked_at = '2026-08-27T08:00:01Z' }
    ) }) -KeyID $keyID
} 'duplicate personal-key records were accepted'

Assert-RevokedPersonalKeyAuthenticationRejected -StatusCode 401
Assert-Throws {
    Assert-RevokedPersonalKeyAuthenticationRejected -StatusCode 200
} 'a successful revoked-key authentication response was accepted'

Write-Host 'Personal-key revocation verifier tests passed.'
