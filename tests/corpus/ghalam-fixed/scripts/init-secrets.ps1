# Creates random secrets in the secrets\ folder (excluded from git and from the Docker build context).
# Existing secrets are not overwritten: losing file_encryption_key means losing all documents.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root 'secrets'
New-Item -ItemType Directory -Force $dir | Out-Null

function New-Secret([string]$Name, [int]$Bytes, [bool]$IsKey) {
    $path = Join-Path $dir $Name
    if ((Test-Path $path) -and ((Get-Item $path).Length -gt 0)) {
        Write-Host "secrets\$Name already exists, left unchanged"
        return
    }
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($buffer)
    $rng.Dispose()
    $value = [Convert]::ToBase64String($buffer)
    if (-not $IsKey) {
        $value = $value.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    [System.IO.File]::WriteAllText($path, $value)
    Write-Host "created secrets\$Name"
}

New-Secret 'postgres_password' 32 $false
New-Secret 'app_db_password' 32 $false
New-Secret 'file_encryption_key' 32 $true
New-Secret 'backup_passphrase' 32 $false

Write-Host 'Keep a copy of file_encryption_key and backup_passphrase in a protected store (password vault, KMS).'
