"""
Test script for alert system functionality.
Tests different threat scenarios and alert generation.
"""

import os
import sys
import asyncio
import json
from datetime import datetime

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from src.alert_manager import AlertManager
from src.threat_analyzer import ThreatAnalyzer

def create_mock_email(subject: str, sender: str) -> dict:
    """Create a mock email for testing."""
    return {
        'payload': {
            'headers': [
                {'name': 'Subject', 'value': subject},
                {'name': 'From', 'value': sender},
                {'name': 'Date', 'value': datetime.now().isoformat()}
            ]
        }
    }

def create_mock_threat_data(score: int, risk_level: str, url: str) -> dict:
    """Create mock threat analysis data."""
    return {
        'score': score,
        'risk_level': risk_level,
        'url': url,
        'category_scores': {
            'domain_age': 0.5,
            'ssl_cert': 0.8,
            'malicious_patterns': 0.3,
            'redirect_chain': 0.2,
            'security_checks': 0.4
        },
        'recommendations': [
            "Test recommendation 1",
            "Test recommendation 2"
        ],
        'scan_time': datetime.now().isoformat(),
        'verdicts': {
            'overall': {'malicious': score > 70},
            'engines': {'malicious': score > 70}
        }
    }

async def test_alerts():
    """Test different alert scenarios."""
    alert_manager = AlertManager()
    
    # Test Case 1: Low Risk Alert
    print("\n🔍 Testing Low Risk Alert...")
    email_data = create_mock_email(
        "Regular Newsletter",
        "newsletter@legitimate-company.com"
    )
    threat_data = create_mock_threat_data(25, "LOW", "https://legitimate-company.com/newsletter")
    alert_manager.process_alert(threat_data, email_data)
    
    # Test Case 2: Medium Risk Alert
    print("\n🔍 Testing Medium Risk Alert...")
    email_data = create_mock_email(
        "Account Update Required",
        "service@company.com"
    )
    threat_data = create_mock_threat_data(55, "MEDIUM", "https://company-service.net/update")
    alert_manager.process_alert(threat_data, email_data)
    
    # Test Case 3: High Risk Alert
    print("\n🔍 Testing High Risk Alert...")
    email_data = create_mock_email(
        "Urgent: Password Reset Required",
        "security@suspicious-domain.com"
    )
    threat_data = create_mock_threat_data(85, "HIGH", "http://suspicious-domain.com/reset")
    alert_manager.process_alert(threat_data, email_data)
    
    # Test Case 4: Critical Risk Alert
    print("\n🔍 Testing Critical Risk Alert...")
    email_data = create_mock_email(
        "Your Account Has Been Compromised",
        "security@fake-bank.com"
    )
    threat_data = create_mock_threat_data(95, "CRITICAL", "http://fake-bank.com/secure")
    alert_manager.process_alert(threat_data, email_data)

    # Test Case 5: PayPal Phishing Attempt
    print("\n🔍 Testing PayPal Phishing Alert...")
    email_data = create_mock_email(
        "PayPal: Unusual Activity Detected",
        "service@paypal-secure-login.com"
    )
    threat_data = create_mock_threat_data(90, "CRITICAL", "http://paypal-secure-login.com/verify")
    threat_data['category_scores']['malicious_patterns'] = 0.9
    threat_data['recommendations'].append("Suspected PayPal phishing attempt")
    alert_manager.process_alert(threat_data, email_data)

    # Test Case 6: Google Drive Share
    print("\n🔍 Testing Drive Share Alert...")
    email_data = create_mock_email(
        "Shared Document: Financial Report",
        "drive-share@suspicious-docs.com"
    )
    threat_data = create_mock_threat_data(75, "HIGH", "http://suspicious-docs.com/view")
    threat_data['category_scores']['domain_age'] = 0.9
    threat_data['recommendations'].append("Suspicious file sharing domain")
    alert_manager.process_alert(threat_data, email_data)
    
    # Verify alert history
    print("\n📋 Checking Alert History...")
    history = alert_manager.get_alert_history()
    print(f"Total alerts in history: {len(history)}")
    
    # Check alerts by risk level
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        level_alerts = alert_manager.get_alert_history(risk_level=level)
        print(f"{level} risk alerts: {len(level_alerts)}")
        
        # Show details of alerts at this level
        if level_alerts:
            print(f"\nDetailed {level} Risk Alerts:")
            for alert in level_alerts:
                print(f"""
    📧 Email: {alert['email_info']['subject']}
    🔗 URL: {alert.get('url', 'No URL')}
    ⚠️ Score: {alert['threat_score']}/100
    🔍 Top Threats:
        {', '.join([f"{k}: {v:.2f}" for k, v in alert['threats'].items() if v > 0.5])}
                """)

if __name__ == "__main__":
    print("🚀 Starting Alert System Tests...")
    print("\nThis test will:")
    print("1. Generate mock emails with varying risk levels")
    print("2. Test alert generation and formatting")
    print("3. Verify desktop notifications")
    print("4. Check alert history storage")
    print("\nWatch for desktop notifications for HIGH and CRITICAL alerts!")
    
    asyncio.run(test_alerts())
    print("\n✅ Alert System Tests Completed")
    print("\n💡 Tip: Check data/alert_history.json for the full alert history")
