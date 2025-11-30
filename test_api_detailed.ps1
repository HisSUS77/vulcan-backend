# Test API scan with detailed output
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
Write-Host "================================"
Write-Host "SCAN RESULTS"
Write-Host "================================"
Write-Host "Scan ID: $($response.id)"
Write-Host "Status: $($response.status)"
Write-Host "Vulnerabilities Found: $($response.vulnerabilities_count)"

if ($response.vulnerabilities) {
    foreach ($vuln in $response.vulnerabilities) {
        Write-Host ""
        Write-Host "--- Vulnerability ---"
        Write-Host "Type: $($vuln.type)"
        Write-Host "Severity: $($vuln.severity)"
        Write-Host "Confidence: $($vuln.confidence)"
        Write-Host "OWASP: $($vuln.owasp)"
        Write-Host "CWE: $($vuln.cwe)"
        
        if ($vuln.analysis) {
            Write-Host ""
            Write-Host "LLM Analysis:"
            if ($vuln.analysis.llm_classification) {
                Write-Host "  Classification: $($vuln.analysis.llm_classification.classification)"
                Write-Host "  Severity: $($vuln.analysis.llm_classification.severity)"
                Write-Host "  Exploitability: $($vuln.analysis.llm_classification.exploitability)"
                Write-Host "  Confidence: $($vuln.analysis.llm_classification.confidence)"
                Write-Host "  Explanation: $($vuln.analysis.llm_classification.explanation)"
                Write-Host "  Remediation: $($vuln.analysis.llm_classification.remediation)"
            }
        }
    }
}
