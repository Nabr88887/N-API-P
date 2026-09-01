function ConvertTo-NewAPIPublicScriptURL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$Origin,
        [Parameter(Mandatory)]
        [string]$Reference
    )

    if ([string]::IsNullOrWhiteSpace($Reference)) {
        return $null
    }

    try {
        $candidate = [Uri]::new($Origin, $Reference)
    } catch {
        return $null
    }

    if ($candidate.Scheme -notin @('http', 'https') -or
        $candidate.Scheme -cne $Origin.Scheme -or
        $candidate.Host -ine $Origin.Host -or
        $candidate.Port -ne $Origin.Port -or
        -not [string]::IsNullOrEmpty($candidate.UserInfo)) {
        return $null
    }
    return $candidate.AbsoluteUri
}

function Get-NewAPIPublicScriptReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$Origin,
        [Parameter(Mandatory)]
        [string]$Html
    )

    $references = [System.Collections.Generic.List[string]]::new()
    $pattern = '<script\b[^>]*\bsrc\s*=\s*["'']([^"'']+)["'']'
    foreach ($match in [regex]::Matches($Html, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $url = ConvertTo-NewAPIPublicScriptURL -Origin $Origin -Reference $match.Groups[1].Value
        if ($null -ne $url -and -not $references.Contains($url)) {
            [void]$references.Add($url)
        }
    }
    return @($references)
}

function Get-NewAPIAsyncChunkReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$Origin,
        [Parameter(Mandatory)]
        [string]$JavaScript
    )

    $marker = 'static/js/async/'
    $markerIndex = $JavaScript.IndexOf($marker, [StringComparison]::Ordinal)
    if ($markerIndex -lt 0) {
        return @()
    }

    $mapStart = $JavaScript.IndexOf('({', $markerIndex, [StringComparison]::Ordinal)
    $mapEnd = if ($mapStart -ge 0) {
        $JavaScript.IndexOf('})[e]', $mapStart, [StringComparison]::Ordinal)
    } else {
        -1
    }
    if ($mapStart -lt 0 -or $mapEnd -le $mapStart) {
        return @()
    }

    $map = $JavaScript.Substring($mapStart + 2, $mapEnd - $mapStart - 2)
    $references = [System.Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches($map, '(?<id>\d+):"(?<hash>[a-f0-9]+)"')) {
        $reference = 'static/js/async/' + $match.Groups['id'].Value + '.' + $match.Groups['hash'].Value + '.js'
        $url = ConvertTo-NewAPIPublicScriptURL -Origin $Origin -Reference $reference
        if ($null -ne $url -and -not $references.Contains($url)) {
            [void]$references.Add($url)
        }
    }
    return @($references)
}

function Get-NewAPIJavaScriptLexicalView {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptBody
    )

    $builder = [Text.StringBuilder]::new()
    $strings = [System.Collections.Generic.List[string]]::new()
    $state = 'code'
    $quote = [char]0
    $escaped = $false
    $stringBuilder = $null
    for ($index = 0; $index -lt $ScriptBody.Length; $index++) {
        $character = $ScriptBody[$index]
        $next = if ($index + 1 -lt $ScriptBody.Length) { $ScriptBody[$index + 1] } else { [char]0 }
        if ($state -eq 'line-comment') {
            if ($character -in @("`r", "`n")) {
                $state = 'code'
                [void]$builder.Append($character)
            } else {
                [void]$builder.Append(' ')
            }
            continue
        }
        if ($state -eq 'block-comment') {
            if ($character -eq '*' -and $next -eq '/') {
                [void]$builder.Append('  ')
                $index++
            } else {
                [void]$builder.Append($(if ($character -in @("`r", "`n")) { $character } else { ' ' }))
            }
            continue
        }
        if ($state -eq 'string') {
            if ($escaped) {
                [void]$stringBuilder.Append($character)
                $escaped = $false
            } elseif ($character -eq '\') {
                [void]$stringBuilder.Append($character)
                $escaped = $true
            } elseif ($character -eq $quote) {
                [void]$strings.Add($stringBuilder.ToString())
                [void]$builder.Append(" __STR$($strings.Count - 1)__ ")
                $stringBuilder = $null
                $state = 'code'
            } else {
                [void]$stringBuilder.Append($character)
            }
            continue
        }
        if ($character -in @("'", '"', '`')) {
            $state = 'string'
            $quote = $character
            $escaped = $false
            $stringBuilder = [Text.StringBuilder]::new()
        } elseif ($character -eq '/' -and $next -eq '/') {
            $state = 'line-comment'
            [void]$builder.Append('  ')
            $index++
        } elseif ($character -eq '/' -and $next -eq '*') {
            $state = 'block-comment'
            [void]$builder.Append('  ')
            $index++
        } else {
            [void]$builder.Append($character)
        }
    }
    return [pscustomobject]@{
        Code = $builder.ToString()
        Strings = @($strings.ToArray())
    }
}

function Get-NewAPITokenContractSignals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptBody
    )

    $lexical = Get-NewAPIJavaScriptLexicalView -ScriptBody $ScriptBody
    $body = $lexical.Code
    $strings = @($lexical.Strings)
    $signals = [ordered]@{
        HasModelLimits = $false
        HasModelLimitsEnabled = $false
        HasTokenRoute = $false
        HasCommaJoinedModelLimits = $false
    }
    $routeIDs = for ($index = 0; $index -lt $strings.Count; $index++) {
        if ($strings[$index] -match '^\/api\/token\/?$') { $index }
    }
    $routeKeyIDs = for ($index = 0; $index -lt $strings.Count; $index++) {
        if ($strings[$index] -in @('url', 'uri', 'path')) { $index }
    }
    $routeMatch = $null
    foreach ($routeID in @($routeIDs)) {
        $placeholder = '__STR' + $routeID + '__'
        $directPattern = '(?:\bfetch|\brequest|\baxios\.[A-Za-z_$][\w$]*)\s*\(\s*' + $placeholder
        $routeKeyPattern = '(?:url|uri|path)'
        if (@($routeKeyIDs).Count -gt 0) {
            $routeKeyPattern += '|__STR(?:' + ((@($routeKeyIDs) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')__'
        }
        $optionsPattern = '(?:\bfetch|\brequest|\baxios\.[A-Za-z_$][\w$]*)\s*\(\s*\{[^{}]{0,4096}?(?:' + $routeKeyPattern + ')\s*:\s*' + $placeholder
        foreach ($pattern in @($directPattern, $optionsPattern)) {
            $candidate = [regex]::Match($body, [string]$pattern, [Text.RegularExpressions.RegexOptions]::Singleline)
            if ($candidate.Success) {
                $routeMatch = $candidate
                break
            }
        }
        if ($null -ne $routeMatch) {
            break
        }
    }
    if ($null -eq $routeMatch -or -not $routeMatch.Success) {
        return [pscustomobject]$signals
    }
    $signals.HasTokenRoute = $true
    $openParen = $body.IndexOf('(', $routeMatch.Index)
    $callEnd = -1
    if ($openParen -ge 0) {
        $depth = 0
        for ($index = $openParen; $index -lt [Math]::Min($body.Length, $openParen + 16384); $index++) {
            if ($body[$index] -eq '(') {
                $depth++
            } elseif ($body[$index] -eq ')') {
                $depth--
                if ($depth -eq 0) {
                    $callEnd = $index
                    break
                }
            }
        }
    }
    if ($callEnd -lt 0) {
        return [pscustomobject]$signals
    }
    $requestText = $body.Substring($routeMatch.Index, $callEnd - $routeMatch.Index + 1)
    $objectPattern = '(?:(?:var|let|const)\s+)?(?<name>[A-Za-z_$][\w$]*)\s*=\s*\{(?<object>[^{}]{0,4096})\}'
    $payloadNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $modelFieldPattern = 'model_limits'
    $modelFieldIDs = for ($index = 0; $index -lt $strings.Count; $index++) {
        if ($strings[$index] -eq 'model_limits') { $index }
    }
    if (@($modelFieldIDs).Count -gt 0) {
        $modelFieldPattern += '|__STR(?:' + ((@($modelFieldIDs) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')__'
    }
    $enabledFieldPattern = 'model_limits_enabled'
    $enabledFieldIDs = for ($index = 0; $index -lt $strings.Count; $index++) {
        if ($strings[$index] -eq 'model_limits_enabled') { $index }
    }
    if (@($enabledFieldIDs).Count -gt 0) {
        $enabledFieldPattern += '|__STR(?:' + ((@($enabledFieldIDs) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')__'
    }
    $payloadKeyIDs = for ($index = 0; $index -lt $strings.Count; $index++) {
        if ($strings[$index] -in @('body', 'data', 'json', 'payload')) { $index }
    }
    $payloadKeyPattern = 'body|data|json|payload'
    if (@($payloadKeyIDs).Count -gt 0) {
        $payloadKeyPattern += '|__STR(?:' + ((@($payloadKeyIDs) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')__'
    }
    foreach ($match in [regex]::Matches($body, $objectPattern, [Text.RegularExpressions.RegexOptions]::Singleline)) {
        $object = $match.Groups['object'].Value
        $hasModel = $object -match '(?:^|[,\s])(?:' + $modelFieldPattern + ')\s*:'
        $hasEnabled = $object -match '(?:^|[,\s])(?:' + $enabledFieldPattern + ')\s*:'
        $joinMatch = [regex]::Match($object, '(?:' + $modelFieldPattern + ')\s*:\s*[^,}]{0,512}\.join\(\s*__STR(?<id>\d+)__\s*\)')
        $hasJoin = $joinMatch.Success -and ([int]$joinMatch.Groups['id'].Value -lt $strings.Count) -and $strings[[int]$joinMatch.Groups['id'].Value] -eq ','
        if ($hasModel -and $hasEnabled -and $hasJoin) {
            [void]$payloadNames.Add($match.Groups['name'].Value)
            $signals.HasModelLimits = $true
            $signals.HasModelLimitsEnabled = $true
            $signals.HasCommaJoinedModelLimits = $true
        }
    }
    $directJoinMatch = [regex]::Match($requestText, '(?:' + $modelFieldPattern + ')\s*:\s*[^}]{0,512}\.join\(\s*__STR(?<id>\d+)__\s*\)')
    $directPayload = $directJoinMatch.Success -and
        ([int]$directJoinMatch.Groups['id'].Value -lt $strings.Count) -and
        $strings[[int]$directJoinMatch.Groups['id'].Value] -eq ',' -and
        $requestText -match '(?:' + $enabledFieldPattern + ')\s*:'
    if ($directPayload) {
        $signals.HasModelLimits = $true
        $signals.HasModelLimitsEnabled = $true
        $signals.HasCommaJoinedModelLimits = $true
    } elseif ($signals.HasModelLimits -and $signals.HasModelLimitsEnabled -and $signals.HasCommaJoinedModelLimits) {
        $boundPayload = $false
        foreach ($name in $payloadNames) {
            if ($requestText -match '(?:' + $payloadKeyPattern + ')\s*:\s*' + [regex]::Escape($name) + '\b') {
                $boundPayload = $true
                break
            }
        }
        if (-not $boundPayload) {
            $signals.HasModelLimits = $false
            $signals.HasModelLimitsEnabled = $false
            $signals.HasCommaJoinedModelLimits = $false
        }
    }
    return [pscustomobject]$signals
}

function ConvertTo-NewAPITokenContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Signals
    )

    if ($Signals.Count -eq 0) {
        throw 'no public JavaScript resources were inspected'
    }
    if (-not (@($Signals | Where-Object HasModelLimits).Count -gt 0)) {
        throw 'public token contract is missing model_limits'
    }
    if (-not (@($Signals | Where-Object HasModelLimitsEnabled).Count -gt 0)) {
        throw 'public token contract is missing model_limits_enabled'
    }
    if (-not (@($Signals | Where-Object HasTokenRoute).Count -gt 0)) {
        throw 'public token contract is missing the /api/token route'
    }
    if (-not (@($Signals | Where-Object HasCommaJoinedModelLimits).Count -gt 0)) {
        throw 'public token contract does not prove comma-joined model_limits encoding'
    }
    if (-not (@($Signals | Where-Object {
        $_.HasModelLimits -and $_.HasModelLimitsEnabled -and $_.HasTokenRoute -and $_.HasCommaJoinedModelLimits
    }).Count -gt 0)) {
        throw 'public token contract evidence is not bound to one request construction'
    }

    return [pscustomobject]@{
        ModelLimitsField = 'model_limits'
        ModelLimitsEnabledField = 'model_limits_enabled'
        TokenRoute = '/api/token/'
        ModelEncoding = 'comma-joined'
    }
}

function Assert-NewAPITokenContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ScriptBodies
    )

    $signals = foreach ($scriptBody in $ScriptBodies) {
        Get-NewAPITokenContractSignals -ScriptBody $scriptBody
    }
    return ConvertTo-NewAPITokenContract -Signals @($signals)
}

function Invoke-NewAPIPublicResourceRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$URL,
        [int]$MaxAttempts = 4,
        [int]$RetryDelayMilliseconds = 750,
        [int]$MaximumRetryDelayMilliseconds = 5000,
        [int]$MaximumBodyBytes = 12MB
    )

    if ($MaxAttempts -lt 1 -or $RetryDelayMilliseconds -lt 0 -or $MaximumRetryDelayMilliseconds -lt $RetryDelayMilliseconds -or $MaximumBodyBytes -lt 1) {
        throw 'invalid public resource request limits'
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $request = [Net.HttpWebRequest]::Create($URL)
        $request.Method = 'GET'
        $request.AllowAutoRedirect = $false
        $request.Proxy = $null
        $request.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate -bor [Net.DecompressionMethods]::Brotli
        $request.Headers['Accept-Encoding'] = 'gzip, deflate, br'
        $request.Headers['Cache-Control'] = 'no-cache'
        $response = $null
        try {
            $response = $request.GetResponse()
            if ([int]$response.StatusCode -ne 200) {
                throw "public resource $URL returned HTTP $([int]$response.StatusCode)"
            }
            $contentType = ($response.ContentType -split ';', 2)[0].Trim().ToLowerInvariant()
            if ($contentType -notin @('text/html', 'text/javascript', 'application/javascript', 'application/x-javascript')) {
                throw "public resource $URL returned an unsupported content type"
            }
            if ($response.ContentLength -gt $MaximumBodyBytes) {
                throw "public resource $URL exceeded the response-size bound"
            }
            $stream = $response.GetResponseStream()
            try {
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
                try {
                    $body = $reader.ReadToEnd()
                } finally {
                    $reader.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
            if ([Text.Encoding]::UTF8.GetByteCount($body) -gt $MaximumBodyBytes) {
                throw "public resource $URL exceeded the response-size bound"
            }
            return $body
        } catch [Net.WebException] {
            $errorResponse = $_.Exception.Response
            $statusCode = if ($null -ne $errorResponse) { [int]$errorResponse.StatusCode } else { 0 }
            if ($statusCode -ne 429 -or $attempt -eq $MaxAttempts) {
                if ($null -ne $errorResponse) {
                    $errorResponse.Dispose()
                }
                throw
            }
            $retryAfter = 0
            if ($null -ne $errorResponse.Headers['Retry-After']) {
                [int]::TryParse($errorResponse.Headers['Retry-After'], [ref]$retryAfter) | Out-Null
            }
            $delay = [Math]::Min($MaximumRetryDelayMilliseconds, [Math]::Max($RetryDelayMilliseconds, $retryAfter * 1000))
            if ($null -ne $errorResponse) {
                $errorResponse.Dispose()
            }
            Start-Sleep -Milliseconds $delay
        } finally {
            if ($null -ne $response) {
                $response.Dispose()
            }
        }
    }
    throw "public resource $URL request exhausted its retry bound"
}

function Invoke-NewAPIPublicTokenContractCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$Origin,
        [int]$MaximumScripts = 150,
        [int]$MinimumRequestDelayMilliseconds = 400,
        [int]$MaxAttempts = 4,
        [int]$MaximumRetryDelayMilliseconds = 5000
    )

    if ($Origin.Scheme -notin @('http', 'https') -or
        [string]::IsNullOrWhiteSpace($Origin.Host) -or
        -not [string]::IsNullOrEmpty($Origin.UserInfo) -or
        $Origin.AbsolutePath -ne '/' -or
        $Origin.Query -ne '' -or
        $Origin.Fragment -ne '') {
        throw 'origin must be an absolute URL without a path, query, or fragment'
    }
    if ($MaximumScripts -lt 1 -or $MinimumRequestDelayMilliseconds -lt 0 -or $MaximumRetryDelayMilliseconds -lt 0) {
        throw 'invalid public token contract traversal limits'
    }

    try {
        $html = Invoke-NewAPIPublicResourceRequest -URL $Origin -MaxAttempts $MaxAttempts -MaximumRetryDelayMilliseconds $MaximumRetryDelayMilliseconds
    } catch {
        throw "public token contract inconclusive: initial page request failed: $($_.Exception.Message)"
    }
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($url in Get-NewAPIPublicScriptReferences -Origin $Origin -Html $html) {
        $queue.Enqueue($url)
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $inspectedSignals = [System.Collections.Generic.List[object]]::new()
    while ($queue.Count -gt 0 -and $seen.Count -lt $MaximumScripts) {
        $url = $queue.Dequeue()
        if (-not $seen.Add($url)) {
            continue
        }
        if ($seen.Count -gt 1 -and $MinimumRequestDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $MinimumRequestDelayMilliseconds
        }
        try {
            $body = Invoke-NewAPIPublicResourceRequest -URL ([Uri]$url) -MaxAttempts $MaxAttempts -MaximumRetryDelayMilliseconds $MaximumRetryDelayMilliseconds
        } catch {
            throw "public token contract inconclusive: resource request failed: $($_.Exception.Message)"
        }
        $signals = Get-NewAPITokenContractSignals -ScriptBody $body
        [void]$inspectedSignals.Add($signals)
        try {
            $contract = ConvertTo-NewAPITokenContract -Signals @($signals)
            return [pscustomobject]@{
                Origin = $Origin.AbsoluteUri
                InspectedScripts = $seen.Count
                Contract = $contract
            }
        } catch {
            foreach ($asyncURL in Get-NewAPIAsyncChunkReferences -Origin $Origin -JavaScript $body) {
                if (-not $seen.Contains($asyncURL)) {
                    $queue.Enqueue($asyncURL)
                }
            }
        }
    }

    if ($queue.Count -gt 0) {
        throw "public token contract inconclusive: traversal limit reached after inspecting $($seen.Count) scripts"
    }
    try {
        ConvertTo-NewAPITokenContract -Signals @($inspectedSignals.ToArray())
    } catch {
        throw "public token contract could not be proven: $($_.Exception.Message)"
    }
}
