function Assert-RevokedPersonalKeyListResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Response,
        [Parameter(Mandatory)]
        [string]$KeyID
    )

    if ([string]::IsNullOrWhiteSpace($KeyID)) {
        throw 'personal-key ID is required'
    }
    if ($null -eq $Response -or $Response.PSObject.Properties.Name -notcontains 'data') {
        throw 'personal-key list response is missing data'
    }

    $matches = @($Response.data | Where-Object { $null -ne $_ -and [string]$_.id -ceq $KeyID })
    if ($matches.Count -ne 1) {
        throw "personal-key list contains $($matches.Count) records for the revoked key"
    }

    $record = $matches[0]
    if ([string]$record.status -cne 'revoked') {
        throw 'personal-key list record is not revoked'
    }
    $revokedAtText = [string]$record.revoked_at
    if ([string]::IsNullOrWhiteSpace($revokedAtText)) {
        throw 'personal-key list record is missing revoked_at'
    }

    $revokedAt = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::RoundtripKind
    if (-not [DateTimeOffset]::TryParse($revokedAtText, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$revokedAt)) {
        throw 'personal-key list record has an invalid revoked_at'
    }

    return $record
}

function Assert-RevokedPersonalKeyAuthenticationRejected {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$StatusCode
    )

    if ($StatusCode -ne 401) {
        throw "revoked personal-key authentication returned HTTP $StatusCode instead of 401"
    }
}

function Assert-PersonalKeyRevokeSucceeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$StatusCode
    )

    if ($StatusCode -ne 204) {
        throw "personal-key revoke returned HTTP $StatusCode instead of 204"
    }
}
