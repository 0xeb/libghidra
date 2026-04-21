param(
    [string]$ProtoRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ProtoRoot {
    param([string]$Override)
    if ($Override -and $Override.Trim().Length -gt 0) {
        return (Resolve-Path $Override).Path
    }
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$root = Resolve-ProtoRoot -Override $ProtoRoot
Write-Host "[run] proto root: $root"

Push-Location $root
try {
    $bufCmd = Get-Command buf -ErrorAction SilentlyContinue
    if ($bufCmd) {
        Write-Host "[run] buf generate"
        & buf generate
        exit $LASTEXITCODE
    }

    Write-Host "[warn] 'buf' not found in PATH."
    Write-Host "[hint] install buf and plugins, then rerun:"
    Write-Host "       buf generate"
    exit 1
}
finally {
    Pop-Location
}
