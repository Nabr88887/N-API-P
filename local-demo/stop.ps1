$ErrorActionPreference = 'Stop'
$envFile = Join-Path $PSScriptRoot '.runtime/demo.env'
$compose = Join-Path $PSScriptRoot 'docker-compose.yml'
if (Test-Path $envFile) {
    Push-Location $PSScriptRoot
    try { docker compose --env-file $envFile -f $compose down } finally { Pop-Location }
}
