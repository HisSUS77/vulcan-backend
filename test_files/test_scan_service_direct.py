"""
Direct test of scan service without API layer
"""
import asyncio
from app.services.scan_service import get_scan_service

async def test_scan():
    service = get_scan_service()
    
    code = """


"""
    
    print("Starting scan...")
    scan_id, input_type = service.start(
        code=code,
        filename="test.py",
        language="python",
        scan_mode="SEMANTIC"
    )
    
    print(f"Scan ID: {scan_id}")
    
    # Wait for scan to complete
    for i in range(10):
        await asyncio.sleep(0.5)
        status_result = service.status(scan_id)
        if status_result.get("state") == "COMPLETED":
            break
    
    # Get summary
    summary_result = service.summary(scan_id)
    
    print("\n=== SCAN SUMMARY ===")
    print(f"Status: {summary_result.get('status') if summary_result else 'Not ready'}")
    print(f"Vulnerabilities: {summary_result.get('vulnerabilities_found') if summary_result else 'N/A'}")
    print(f"By Severity: {summary_result.get('by_severity') if summary_result else 'N/A'}")
    
    # Get logs
    logs_result = service.logs(scan_id)
    print("\n=== LOGS ===")
    for log in logs_result.get("logs", []):
        print(log)
    
    # Get vulnerabilities  
    print("\n=== VULNERABILITIES ===")
    if summary_result and "vulnerabilities" in summary_result:
        for vuln in summary_result["vulnerabilities"]:
            print(f"- {vuln.get('type')}: {vuln.get('severity')}")
    else:
        print("Summary not ready or no vulnerabilities field")

if __name__ == "__main__":
    asyncio.run(test_scan())
