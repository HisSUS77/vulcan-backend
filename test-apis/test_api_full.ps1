# Login first
Write-Host "Logging in..."
$loginBody = @{
    email = "admin@vulcan.ai"
    password = "admin123!"
} | ConvertTo-Json

$loginResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -ErrorAction Stop
$token = $loginResponse.access_token
Write-Host "Logged in successfully"

# Prepare code for scan
$code = @'
import os
import sys

user_input = sys.argv[1]
os.system(user_input)
'@

$body = @{
    code = $code
    filename = "vulnerable_test.py"
    language = "python"
} | ConvertTo-Json

Write-Host "`nStarting scan..."
$headers = @{
    Authorization = "Bearer $token"
}
$response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/start" -Method Post -Body $body -ContentType "application/json" -Headers $headers
$scanId = $response.scan_id
Write-Host "Scan started: $scanId"

Start-Sleep -Seconds 3

Write-Host "`nGetting summary..."
$summary = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$scanId/summary" -Method Get -Headers $headers

Write-Host "`n=== SCAN SUMMARY ==="
$summary | ConvertTo-Json -Depth 10
