param($scanId)

$loginBody = @{
    email = "admin@vulcan.ai"
    password = "admin123!"
} | ConvertTo-Json

$loginResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
$token = $loginResponse.access_token

$headers = @{
    Authorization = "Bearer $token"
}

# Get the logs
$logs = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$scanId/logs" -Method Get -Headers $headers
Write-Host "=== SCAN LOGS FOR $scanId ==="
$logs.logs | ForEach-Object { Write-Host $_ }

# Get status
Write-Host "`n=== STATUS ==="
$status = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$scanId/status" -Method Get -Headers $headers
$status | ConvertTo-Json
