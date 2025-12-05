# Test API scan with queries.json
$code = @"
import sqlite3

def check_user(sqli):
    if sqli:
        username = sqli.get("username")
        try:
            conn = sqlite3.connect('users.db')
            cur = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}'"
            cur.execute(query)
            result = cur.fetchall()
            return result
        except:
            pass
"@

$body = @{
    filename = "test_sqli.py"
    code = $code
    language = "python"
    scanMode = "FULL"
} | ConvertTo-Json

Write-Host "Sending scan request..."
$response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scan" -Method POST -Body $body -ContentType "application/json"

Write-Host ""
Write-Host "Scan completed!"
Write-Host "Scan ID: $($response.id)"
Write-Host "Status: $($response.status)"
Write-Host "Vulnerabilities Found: $($response.vulnerabilities_count)"

if ($response.vulnerabilities) {
    Write-Host ""
    Write-Host "Detected Vulnerabilities:"
    foreach ($vuln in $response.vulnerabilities) {
        Write-Host ""
        Write-Host "  Type: $($vuln.type)"
        Write-Host "  Severity: $($vuln.severity)"
        Write-Host "  Confidence: $($vuln.confidence)"
        Write-Host "  OWASP: $($vuln.owasp)"
        Write-Host "  CWE: $($vuln.cwe)"
    }
}
