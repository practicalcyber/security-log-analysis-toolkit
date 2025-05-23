#!/usr/bin/env python3
"""
Security Log Analysis Toolkit - API Test Script
Tests the main API endpoints to ensure everything is working correctly.
"""

import requests
import json
import time
import sys
from pathlib import Path

# Configuration
API_BASE = "http://localhost:8000/api"
AUTH_TOKEN = "demo-token-123"
HEADERS = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
    "Content-Type": "application/json"
}

def print_test(test_name):
    """Print test header"""
    print(f"\n🧪 Testing: {test_name}")
    print("-" * 50)

def print_success(message):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message):
    """Print error message"""
    print(f"❌ {message}")

def test_health_check():
    """Test basic API health"""
    print_test("API Health Check")
    
    try:
        response = requests.get(f"{API_BASE.replace('/api', '')}/")
        if response.status_code == 200:
            data = response.json()
            print_success(f"API is healthy: {data.get('message', 'OK')}")
            return True
        else:
            print_error(f"Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Health check failed: {e}")
        return False

def test_upload_logs():
    """Test log file upload"""
    print_test("Log File Upload")
    
    # Create sample log content
    sample_log = """2024-01-15 08:15:30 Event ID: 4624 An account was successfully logged on Account Name: testuser Source Network Address: 192.168.1.100 Logon Type: 2
2024-01-15 08:16:42 Event ID: 4625 An account failed to log on Account Name: admin Source Network Address: 203.0.113.1 Logon Type: 3
Jan 15 08:17:30 testserver sshd[12345]: Failed password for root from 203.0.113.1 port 22 ssh2
Jan 15 08:18:15 testserver sshd[12346]: Accepted password for user from 10.0.0.50 port 22 ssh2"""
    
    try:
        # Prepare file upload
        files = {
            'file': ('test_logs.txt', sample_log, 'text/plain')
        }
        
        # Remove Content-Type for file upload
        upload_headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        
        response = requests.post(
            f"{API_BASE}/upload-logs",
            headers=upload_headers,
            files=files
        )
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Upload successful: {data.get('message', 'OK')}")
            return True
        else:
            print_error(f"Upload failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print_error(f"Upload test failed: {e}")
        return False

def test_get_logs():
    """Test retrieving logs"""
    print_test("Retrieve Logs")
    
    try:
        response = requests.get(f"{API_BASE}/logs", headers=HEADERS)
        
        if response.status_code == 200:
            logs = response.json()
            print_success(f"Retrieved {len(logs)} log entries")
            
            if logs:
                print(f"📄 Sample log entry:")
                sample = logs[0]
                for key, value in sample.items():
                    print(f"   {key}: {value}")
                return logs
            else:
                print("ℹ️  No logs found (this is normal for a fresh installation)")
                return []
        else:
            print_error(f"Failed to retrieve logs: {response.status_code}")
            return None
            
    except Exception as e:
        print_error(f"Get logs test failed: {e}")
        return None

def test_analysis(log_ids):
    """Test log analysis"""
    print_test("Log Analysis")
    
    if not log_ids:
        print("⚠️  Skipping analysis test - no logs available")
        return None
    
    try:
        # Take first few log IDs for analysis
        test_ids = log_ids[:min(5, len(log_ids))]
        
        analysis_request = {
            "log_entries": test_ids,
            "analysis_type": "suspicious_activity",
            "llm_provider": "openai"
        }
        
        response = requests.post(
            f"{API_BASE}/analyze",
            headers=HEADERS,
            json=analysis_request
        )
        
        if response.status_code == 200:
            results = response.json()
            print_success("Analysis completed successfully")
            
            # Display results summary
            if 'failed_logins' in results:
                failed_count = results['failed_logins'].get('total_failed', 0)
                alerts_count = len(results['failed_logins'].get('alerts', []))
                print(f"   Failed logins detected: {failed_count}")
                print(f"   Security alerts: {alerts_count}")
            
            if 'time_patterns' in results:
                off_hours = results['time_patterns'].get('off_hours_count', 0)
                print(f"   Off-hours events: {off_hours}")
            
            if 'threat_intelligence' in results:
                ip_count = len(results['threat_intelligence'])
                print(f"   IPs analyzed: {ip_count}")
            
            return results
        else:
            print_error(f"Analysis failed: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print_error(f"Analysis test failed: {e}")
        return None

def test_report_generation(log_ids):
    """Test report generation"""
    print_test("Report Generation")
    
    if not log_ids:
        print("⚠️  Skipping report test - no logs available")
        return None
    
    try:
        test_ids = log_ids[:min(3, len(log_ids))]
        
        report_request = {
            "analysis_type": "executive",
            "log_ids": test_ids
        }
        
        response = requests.post(
            f"{API_BASE}/generate-report",
            headers=HEADERS,
            json=report_request
        )
        
        if response.status_code == 200:
            report = response.json()
            print_success(f"Report generated: {report.get('title', 'Untitled')}")
            print(f"   Report ID: {report.get('id')}")
            print(f"   Created: {report.get('created_at')}")
            return report.get('id')
        else:
            print_error(f"Report generation failed: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print_error(f"Report generation test failed: {e}")
        return None

def test_get_reports():
    """Test retrieving reports"""
    print_test("Retrieve Reports")
    
    try:
        response = requests.get(f"{API_BASE}/reports", headers=HEADERS)
        
        if response.status_code == 200:
            reports = response.json()
            print_success(f"Retrieved {len(reports)} reports")
            
            for report in reports[-3:]:  # Show last 3 reports
                print(f"   📋 {report.get('title')} ({report.get('report_type')})")
            
            return reports
        else:
            print_error(f"Failed to retrieve reports: {response.status_code}")
            return None
            
    except Exception as e:
        print_error(f"Get reports test failed: {e}")
        return None

def main():
    """Run all tests"""
    print("🛡️  Security Log Analysis Toolkit - API Test Suite")
    print("=" * 60)
    
    # Test counter
    passed = 0
    total = 0
    
    # 1. Health check
    total += 1
    if test_health_check():
        passed += 1
    else:
        print("💥 API is not accessible. Make sure the service is running.")
        sys.exit(1)
    
    # 2. Upload test logs
    total += 1
    if test_upload_logs():
        passed += 1
        time.sleep(2)  # Give time for processing
    
    # 3. Retrieve logs
    total += 1
    logs = test_get_logs()
    if logs is not None:
        passed += 1
        log_ids = [log['id'] for log in logs] if logs else []
    else:
        log_ids = []
    
    # 4. Analysis test
    total += 1
    analysis_results = test_analysis(log_ids)
    if analysis_results is not None:
        passed += 1
    
    # 5. Report generation
    total += 1
    report_id = test_report_generation(log_ids)
    if report_id is not None:
        passed += 1
        time.sleep(1)  # Give time for report creation
    
    # 6. Retrieve reports
    total += 1
    if test_get_reports() is not None:
        passed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"🏁 Test Summary: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your security toolkit is working correctly.")
        print("\n📝 Next steps:")
        print("   1. Open http://localhost in your browser")
        print("   2. Upload your own log files")
        print("   3. Configure LLM API keys for enhanced analysis")
        print("   4. Explore the analysis and reporting features")
    else:
        print(f"⚠️  {total - passed} test(s) failed. Check the error messages above.")
        print("   Make sure all services are running: docker-compose ps")
        print("   Check logs: docker-compose logs -f")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)