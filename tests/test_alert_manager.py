"""Unit tests for alert management functionality."""

import pytest
import os
import json
from datetime import datetime
from src.alert_manager import AlertManager

@pytest.fixture
def alert_manager(tmp_path):
    """Create AlertManager instance with temporary storage."""
    # Ensure test directory exists
    test_dir = tmp_path / "alerts"
    test_dir.mkdir(exist_ok=True)
    history_path = test_dir / "test_alert_history.json"
    return AlertManager(alert_history_path=str(history_path))

@pytest.fixture
def sample_threat_data():
    """Create sample threat analysis data."""
    return {
        'score': 85,
        'risk_level': 'HIGH',
        'category_scores': {
            'domain_age': 0.8,
            'ssl_cert': 0.6,
            'malicious_patterns': 0.7,
            'redirect_chain': 0.4,
            'security_checks': 0.9
        },
        'recommendations': [
            "Recently registered domain detected. Exercise extreme caution.",
            "SSL certificate issues detected. Verify website legitimacy."
        ],
        'scan_time': datetime.now().isoformat(),
        'verdicts': {
            'overall': {'malicious': True},
            'engines': {'malicious': True}
        }
    }

@pytest.fixture
def sample_email_data():
    """Create sample email data."""
    return {
        'payload': {
            'headers': [
                {'name': 'Subject', 'value': 'Test Subject'},
                {'name': 'From', 'value': 'sender@example.com'},
                {'name': 'Date', 'value': datetime.now().isoformat()}
            ]
        }
    }

def test_format_alert(alert_manager, sample_threat_data, sample_email_data):
    """Test alert data formatting."""
    alert = alert_manager.format_alert(sample_threat_data, sample_email_data)
    
    # Verify alert structure
    assert 'timestamp' in alert
    assert 'risk_level' in alert
    assert 'threat_score' in alert
    assert 'email_info' in alert
    assert 'threats' in alert
    assert 'recommendations' in alert
    assert 'scan_data' in alert
    
    # Verify content
    assert alert['risk_level'] == 'HIGH'
    assert alert['threat_score'] == 85
    assert alert['email_info']['subject'] == 'Test Subject'
    assert alert['email_info']['sender'] == 'sender@example.com'
    assert len(alert['recommendations']) == 2

def test_generate_alert_message(alert_manager, sample_threat_data, sample_email_data):
    """Test alert message generation in different formats."""
    # Format alert data
    alert_data = alert_manager.format_alert(sample_threat_data, sample_email_data)
    
    # Test text format
    text_message = alert_manager.generate_alert_message(alert_data, format='text')
    assert '⚠️ HIGH THREAT DETECTED ⚠️' in text_message
    assert 'Score: 85/100' in text_message
    assert 'Test Subject' in text_message
    assert 'sender@example.com' in text_message
    
    # Test HTML format
    html_message = alert_manager.generate_alert_message(alert_data, format='html')
    assert '<h2' in html_message
    assert 'HIGH THREAT DETECTED' in html_message
    assert 'Test Subject' in html_message
    assert 'sender@example.com' in html_message

def test_alert_history(alert_manager, sample_threat_data, sample_email_data):
    """Test alert history storage and retrieval."""
    # Process some alerts
    alert_manager.process_alert(sample_threat_data, sample_email_data)
    
    # Modify risk level and process another alert
    low_risk_data = sample_threat_data.copy()
    low_risk_data['risk_level'] = 'LOW'
    low_risk_data['score'] = 25
    alert_manager.process_alert(low_risk_data, sample_email_data)
    
    # Test history retrieval
    all_alerts = alert_manager.get_alert_history()
    assert len(all_alerts) == 2
    
    # Test filtering by risk level
    high_alerts = alert_manager.get_alert_history(risk_level='HIGH')
    assert len(high_alerts) == 1
    assert high_alerts[0]['risk_level'] == 'HIGH'
    
    low_alerts = alert_manager.get_alert_history(risk_level='LOW')
    assert len(low_alerts) == 1
    assert low_alerts[0]['risk_level'] == 'LOW'

def test_alert_history_persistence(tmp_path, sample_threat_data, sample_email_data):
    """Test that alert history is properly saved and loaded."""
    history_path = tmp_path / "persist_test_history.json"
    os.makedirs(tmp_path, exist_ok=True)
    
    # Create first instance and add alert
    manager1 = AlertManager(alert_history_path=str(history_path))
    manager1.process_alert(sample_threat_data, sample_email_data)
    
    # Create second instance and verify history is loaded
    manager2 = AlertManager(alert_history_path=str(history_path))
    loaded_history = manager2.get_alert_history()
    
    assert len(loaded_history) == 1
    assert loaded_history[0]['risk_level'] == 'HIGH'

def test_desktop_notification(alert_manager, sample_threat_data, sample_email_data, monkeypatch):
    """Test desktop notification functionality."""
    notification_sent = False
    
    def mock_send_notification(*args, **kwargs):
        nonlocal notification_sent
        notification_sent = True
    
    # Mock platform-specific notification functions
    if alert_manager.platform == 'Windows':
        monkeypatch.setattr("win10toast.ToastNotifier.show_toast", mock_send_notification)
    elif alert_manager.platform == 'Darwin':
        def mock_system(cmd):
            nonlocal notification_sent
            if 'terminal-notifier' in cmd:
                notification_sent = True
        monkeypatch.setattr("os.system", mock_system)
    elif alert_manager.platform == 'Linux':
        def mock_system(cmd):
            nonlocal notification_sent
            if 'notify-send' in cmd:
                notification_sent = True
        monkeypatch.setattr("os.system", mock_system)
    
    # Process high-risk alert
    alert_manager.process_alert(sample_threat_data, sample_email_data)
    assert notification_sent
    
    # Reset and process low-risk alert
    notification_sent = False
    low_risk_data = sample_threat_data.copy()
    low_risk_data['risk_level'] = 'LOW'
    low_risk_data['score'] = 25
    alert_manager.process_alert(low_risk_data, sample_email_data)
    assert not notification_sent  # Should not notify for low-risk alerts
