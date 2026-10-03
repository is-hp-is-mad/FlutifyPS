$ErrorActionPreference = 'Stop'
$certificateDirectory = Join-Path $PSScriptRoot '..\cert'
New-Item -ItemType Directory -Path $certificateDirectory -Force | Out-Null
$keyPath = Join-Path $certificateDirectory 'server.key'
$certPath = Join-Path $certificateDirectory 'server.crt'
if ((Test-Path -LiteralPath $keyPath) -or (Test-Path -LiteralPath $certPath)) { throw 'Certificate files already exist; refusing to overwrite.' }
$sansValue = if ($env:SANS) { $env:SANS } else { 'DNS:localhost,IP:127.0.0.1,IP:::1' }
$daysValue = if ($env:DAYS) { [int]$env:DAYS } else { 90 }
& openssl req -config (Join-Path $PSScriptRoot 'openssl.cnf') -x509 -nodes -newkey rsa:2048 -sha256 -keyout $keyPath -out $certPath -days $daysValue -subj '/CN=localhost' -addext "subjectAltName=$sansValue" -addext 'extendedKeyUsage=serverAuth'
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL certificate generation failed.' }
Write-Output 'Created cert/server.key and cert/server.crt for local development; restrict the private key ACL to the service account.'
