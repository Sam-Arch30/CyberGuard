$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runtimeRoot = Join-Path $projectRoot '.local-runtime'
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
$pythonPath = Join-Path $projectRoot 'backend/venv/Scripts/python.exe'
if (!(Test-Path -LiteralPath $pythonPath)) { throw 'Install backend dependencies in backend/venv first.' }
foreach ($localPort in @(8000,5173)) {
    if (Get-NetTCPConnection -LocalPort $localPort -State Listen -ErrorAction SilentlyContinue) { throw "Port $localPort is occupied. Stop the existing development server first." }
}
$dbPath = Join-Path $projectRoot 'backend/data/mailtrace.db'
if (Test-Path -LiteralPath $dbPath) {
    $backupPath = Join-Path $runtimeRoot ('mailtrace-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.db')
    & $pythonPath -c 'import sqlite3,sys; source=sqlite3.connect(sys.argv[1]); target=sqlite3.connect(sys.argv[2]); source.backup(target); target.close(); source.close()' $dbPath $backupPath
    if ($LASTEXITCODE -ne 0) { throw 'Backup failed; startup cancelled.' }
}
$env:CYBERGUARD_SERVER_CREDENTIALS = '{}'
$env:CYBERGUARD_REQUIRE_AUTH = 'false'
$env:CYBERGUARD_DEMO_MODE = 'true'
$env:VITE_LOCAL_DEMO = 'true'
$env:CYBERGUARD_ENV = 'DEVELOPMENT'
$env:ENVIRONMENT = 'development'
$env:ALLOW_WORKSPACE_RESET = 'false'
$env:VITE_API_BASE_URL = '' # Use Vite's same-origin /api proxy for local browser requests.
$backendProcess = Start-Process -FilePath $pythonPath -ArgumentList '-m','uvicorn','backend.main:app','--host','127.0.0.1','--port','8000' -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeRoot 'backend.log') -RedirectStandardError (Join-Path $runtimeRoot 'backend-errors.log')
$nodePath = (Get-Command node.exe).Source
$frontendProcess = Start-Process -FilePath $nodePath -ArgumentList 'node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5173','--strictPort' -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeRoot 'frontend.log') -RedirectStandardError (Join-Path $runtimeRoot 'frontend-errors.log')
@{ backend = $backendProcess.Id; frontend = $frontendProcess.Id } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimeRoot 'processes.json')
Write-Host 'Open http://127.0.0.1:5173. Local prototype mode: no access token or sign-in required.'
