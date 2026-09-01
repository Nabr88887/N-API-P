$ErrorActionPreference = 'Stop'

$verifier = Join-Path $PSScriptRoot 'newapi-token-contract-verifier.ps1'
if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw 'NewAPI token contract verifier is missing'
}
. $verifier

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) {
        throw $message
    }
}

$origin = [Uri]'http://localhost:3000/'
$html = @'
<!doctype html>
<script src="/static/js/index.js"></script>
<script src="https://cdn.example.invalid/ignored.js"></script>
<script src="https://localhost:3000/cross-scheme.js"></script>
<script src="http://user:password@localhost:3000/embedded-credential.js"></script>
<script src="data:text/javascript,ignored"></script>
'@
$scriptReferences = @(Get-NewAPIPublicScriptReferences -Origin $origin -Html $html)
Assert-True ($scriptReferences.Count -eq 1 -and $scriptReferences[0] -eq 'http://localhost:3000/static/js/index.js') 'same-origin script parsing accepted an unexpected reference'

$runtime = 'c.u=e=>"static/js/async/"+e+"."+({1799:"069fa2192f",1982:"eb78d4a925"})[e]+".js"'
$chunkReferences = @(Get-NewAPIAsyncChunkReferences -Origin $origin -JavaScript $runtime)
Assert-True ($chunkReferences.Count -eq 2) 'Rspack async chunk map did not yield both chunks'
Assert-True ($chunkReferences -contains 'http://localhost:3000/static/js/async/1799.069fa2192f.js') 'Rspack async chunk URL was constructed incorrectly'

$invalidLimitsRejected = $false
try {
    Invoke-NewAPIPublicResourceRequest -URL $origin -RetryDelayMilliseconds 1000 -MaximumRetryDelayMilliseconds 500 | Out-Null
} catch {
    $invalidLimitsRejected = $true
}
Assert-True $invalidLimitsRejected 'a retry cap below the base delay was accepted'

$invalidOriginRejected = $false
try {
    Invoke-NewAPIPublicTokenContractCheck -Origin ([Uri]'file:///tmp/') -MaximumScripts 1 | Out-Null
} catch {
    $invalidOriginRejected = $true
}
Assert-True $invalidOriginRejected 'a non-HTTP contract origin was accepted'

$validContract = 'let body={model_limits:e.model_limits.join(","),model_limits_enabled:e.model_limits.length>0}; fetch("/api/token/",{body:body})'
$evidence = Assert-NewAPITokenContract -ScriptBodies @($validContract)
Assert-True ($evidence.ModelLimitsField -eq 'model_limits' -and $evidence.ModelEncoding -eq 'comma-joined') 'valid token contract was not recognized'
$quotedEvidence = Assert-NewAPITokenContract -ScriptBodies @('let body={"model_limits":e.model_limits.join(","),"model_limits_enabled":e.model_limits.length>0}; request({"url":"/api/token/","body":body})')
Assert-True ($quotedEvidence.TokenRoute -eq '/api/token/') 'quoted token contract was not recognized'
$inlineEvidence = Assert-NewAPITokenContract -ScriptBodies @('fetch("/api/token/",{body:{model_limits:e.model_limits.join(","),model_limits_enabled:true}})')
Assert-True ($inlineEvidence.ModelEncoding -eq 'comma-joined') 'inline token payload was not recognized'

$splitRejected = $false
try {
    Assert-NewAPITokenContract -ScriptBodies @(
    'let body={model_limits:e.model_limits.join(","),model_limits_enabled:e.model_limits.length>0};',
    'fetch("/api/token/",{body:body})'
) | Out-Null
} catch {
    $splitRejected = $true
}
Assert-True $splitRejected 'token contract evidence was incorrectly combined across unrelated scripts'

$commentOnlyRejected = $false
try {
    Assert-NewAPITokenContract -ScriptBodies @('/* model_limits model_limits_enabled /api/token/ model_limits.join(",") */') | Out-Null
} catch {
    $commentOnlyRejected = $true
}
Assert-True $commentOnlyRejected 'comment text was treated as token contract evidence'

$quotedFakeRejected = $false
try {
    Assert-NewAPITokenContract -ScriptBodies @('"fetch(\"/api/token/\",{model_limits:e.model_limits.join(\",\"),model_limits_enabled:true})"') | Out-Null
} catch {
    $quotedFakeRejected = $true
}
Assert-True $quotedFakeRejected 'JavaScript string text was treated as token contract evidence'

$unrelatedRequestRejected = $false
try {
    Assert-NewAPITokenContract -ScriptBodies @('let body={model_limits:e.model_limits.join(","),model_limits_enabled:true}; fetch("/api/other",{body:body}); fetch("/api/token/",{body:{}})') | Out-Null
} catch {
    $unrelatedRequestRejected = $true
}
Assert-True $unrelatedRequestRejected 'token fields from an unrelated request were accepted'

$embeddedRequestRejected = $false
try {
    Assert-NewAPITokenContract -ScriptBodies @('let body={model_limits:e.model_limits.join(","),model_limits_enabled:true}; myrequest("/api/token/",{body:body})') | Out-Null
} catch {
    $embeddedRequestRejected = $true
}
Assert-True $embeddedRequestRejected 'an embedded non-request identifier was treated as a token request'

foreach ($invalidContract in @(
    'let body={models:e.models}; fetch("/api/token/",{body:body})',
    'let body={model_limits:e.model_limits.join(",")}; fetch("/api/token/",{body:body})',
    'let body={model_limits:e.model_limits.join(","),model_limits_enabled:true}; fetch("/api/other",{body:body})'
)) {
    $rejected = $false
    try {
        Assert-NewAPITokenContract -ScriptBodies @($invalidContract) | Out-Null
    } catch {
        $rejected = $true
    }
    Assert-True $rejected 'an incomplete or unrelated token contract was accepted'
}

Write-Host 'NewAPI token contract verifier tests passed.'
