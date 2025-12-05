# Test script to verify graph endpoint works with singleton pattern

Write-Host "1. Logging in as admin..." -ForegroundColor Cyan
$loginResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -Headers @{"Content-Type"="application/json"} -Body '{"email":"admin@vulcan.ai","password":"admin123!"}'
$token = $loginResponse.access_token
Write-Host "   Token obtained: $($token.Substring(0,20))..." -ForegroundColor Green

Write-Host "`n2. Starting a scan with vulnerable code..." -ForegroundColor Cyan
$vulnerableCode = @"
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f\"SELECT * FROM users WHERE username = '{username}'\"
    cursor.execute(query)
    return cursor.fetchone()
"@

$scanBody = @{
    code = $vulnerableCode
    language = "python"
} | ConvertTo-Json

$scanResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/start" -Method POST -Headers @{"Authorization"="Bearer $token"; "Content-Type"="application/json"} -Body $scanBody
$scanId = $scanResponse.scan_id
Write-Host "   Scan started: $scanId" -ForegroundColor Green

Write-Host "`n3. Waiting for scan to complete..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

Write-Host "`n4. Checking scan status..." -ForegroundColor Cyan
$status = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$scanId/status" -Headers @{"Authorization"="Bearer $token"}
Write-Host "   Status: $($status.status)" -ForegroundColor Green
Write-Host "   Vulnerabilities: $($status.vulnerabilities_found)" -ForegroundColor $(if($status.vulnerabilities_found -gt 0){'Yellow'}else{'Green'})

Write-Host "`n5. Getting scan summary..." -ForegroundColor Cyan
$summary = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$scanId/summary" -Headers @{"Authorization"="Bearer $token"}
Write-Host "   Files scanned: $($summary.files_scanned)" -ForegroundColor Green
Write-Host "   Vulnerabilities: $($summary.vulnerabilities_found)" -ForegroundColor Yellow

Write-Host "`n6. Requesting AST graph..." -ForegroundColor Cyan
try {
    $astGraph = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/graphs/$scanId/file/inline_code?type=AST" -Headers @{"Authorization"="Bearer $token"}
    Write-Host "   Graph type: $($astGraph.type)" -ForegroundColor Green
    Write-Host "   Nodes: $($astGraph.nodes.Count)" -ForegroundColor Green
    Write-Host "   Edges: $($astGraph.edges.Count)" -ForegroundColor Green
    
    if ($astGraph.nodes.Count -gt 0) {
        Write-Host "`n✅ SUCCESS! Graph data retrieved!" -ForegroundColor Green
        Write-Host "First 3 nodes:" -ForegroundColor Cyan
        $astGraph.nodes | Select-Object -First 3 | ForEach-Object {
            Write-Host "  - $($_.label) [$($_.type)]" -ForegroundColor White
        }
    } else {
        Write-Host "`n❌ FAILED: Graph has 0 nodes" -ForegroundColor Red
        if ($astGraph.error) {
            Write-Host "   Error: $($astGraph.error)" -ForegroundColor Red
            Write-Host "   Detail: $($astGraph.detail)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "`n❌ FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n7. Requesting CFG graph..." -ForegroundColor Cyan
try {
    $cfgGraph = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/graphs/$scanId/file/inline_code?type=CFG" -Headers @{"Authorization"="Bearer $token"}
    Write-Host "   CFG Nodes: $($cfgGraph.nodes.Count)" -ForegroundColor Green
    Write-Host "   CFG Edges: $($cfgGraph.edges.Count)" -ForegroundColor Green
} catch {
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nTest complete!" -ForegroundColor Cyan
