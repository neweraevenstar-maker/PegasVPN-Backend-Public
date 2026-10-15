# Offline-only backend checks for Windows PowerShell. No live VPN access.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$env:PEGASVPN_DEPLOYMENT = 'tests'
$env:PEGASVPN_TEST_DATA_DIR = Join-Path ([IO.Path]::GetTempPath()) ("pegasvpn-tests-" + [Guid]::NewGuid().ToString("N"))
Remove-Item Env:PEGASVPN_DB_PATH -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $env:PEGASVPN_TEST_DATA_DIR | Out-Null
try {
    python -m pip install -r requirements-auth.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
    python -m compileall -q .
    if ($LASTEXITCODE -ne 0) { throw 'Python syntax check failed' }
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed' }
} finally {
    Remove-Item -LiteralPath $env:PEGASVPN_TEST_DATA_DIR -Recurse -Force
    Remove-Item Env:PEGASVPN_TEST_DATA_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:PEGASVPN_DEPLOYMENT -ErrorAction SilentlyContinue
}
