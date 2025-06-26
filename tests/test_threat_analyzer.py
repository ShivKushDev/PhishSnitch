"""Unit tests for threat analysis functionality."""

import pytest
import requests
from datetime import datetime, timedelta
from src.threat_analyzer import ThreatAnalyzer

@pytest.fixture
def threat_analyzer():
    """Create ThreatAnalyzer instance with test configuration."""
    return ThreatAnalyzer(api_key="test-api-key")

def test_analyze_domain_age():
    """Test domain age risk scoring."""
    analyzer = ThreatAnalyzer(api_key="test-api-key")
    
    # Test very new domain (highest risk)
    new_domain = {
        'creationDate': (datetime.now() - timedelta(days=3)).isoformat()
    }
    assert analyzer.analyze_domain_age(new_domain) == 1.0
    
    # Test moderately new domain
    recent_domain = {
        'creationDate': (datetime.now() - timedelta(days=20)).isoformat()
    }
    assert analyzer.analyze_domain_age(recent_domain) == 0.7
    
    # Test established domain
    old_domain = {
        'creationDate': (datetime.now() - timedelta(days=400)).isoformat()
    }
    assert analyzer.analyze_domain_age(old_domain) == 0.0

def test_analyze_ssl_cert():
    """Test SSL certificate risk scoring."""
    analyzer = ThreatAnalyzer(api_key="test-api-key")
    
    # Test expired certificate
    expired_cert = {
        'validFrom': (datetime.now() - timedelta(days=400)).isoformat(),
        'validTo': (datetime.now() - timedelta(days=30)).isoformat(),
        'issuer': {'O': 'Unknown CA'}
    }
    assert analyzer.analyze_ssl_cert(expired_cert) > 0.5
    
    # Test valid, trusted certificate
    valid_cert = {
        'validFrom': (datetime.now() - timedelta(days=30)).isoformat(),
        'validTo': (datetime.now() + timedelta(days=300)).isoformat(),
        'issuer': {'O': 'DigiCert Inc'}
    }
    assert analyzer.analyze_ssl_cert(valid_cert) < 0.3
    
    # Test missing certificate
    assert analyzer.analyze_ssl_cert({}) == 1.0

def test_analyze_redirect_chain():
    """Test redirect chain analysis."""
    analyzer = ThreatAnalyzer(api_key="test-api-key")
    
    # Test no redirects
    assert analyzer.analyze_redirect_chain([]) == 0.0
    
    # Test simple redirect
    simple_chain = ['https://example.com', 'https://example.com/page']
    assert analyzer.analyze_redirect_chain(simple_chain) < 0.3
    
    # Test suspicious chain with URL shorteners
    suspicious_chain = [
        'https://example.com',
        'https://bit.ly/abc123',
        'http://suspicious.com',
        'https://malicious.com'
    ]
    assert analyzer.analyze_redirect_chain(suspicious_chain) > 0.5

def test_get_risk_level():
    """Test risk level categorization."""
    analyzer = ThreatAnalyzer(api_key="test-api-key")
    
    assert analyzer._get_risk_level(0.9) == 'CRITICAL'
    assert analyzer._get_risk_level(0.7) == 'HIGH'
    assert analyzer._get_risk_level(0.5) == 'MEDIUM'
    assert analyzer._get_risk_level(0.3) == 'LOW'
    assert analyzer._get_risk_level(0.1) == 'SAFE'

def test_calculate_threat_score():
    """Test overall threat score calculation."""
    analyzer = ThreatAnalyzer(api_key="test-api-key")
    
    # Test high-risk scenario
    high_risk_results = {
        'domain': {
            'creationDate': (datetime.now() - timedelta(days=2)).isoformat()
        },
        'cert': {},  # Missing certificate
        'redirects': [
            'https://example.com',
            'https://bit.ly/abc123',
            'http://suspicious.com'
        ],
        'patterns': ['login-form', 'suspicious-redirect'],
        'verdicts': {
            'overall': {'malicious': True},
            'engines': {'malicious': True}
        }
    }
    
    result = analyzer.calculate_threat_score(high_risk_results)
    assert result['score'] >= 80
    assert result['risk_level'] == 'CRITICAL'
    assert len(result['recommendations']) >= 3
    
    # Test low-risk scenario
    low_risk_results = {
        'domain': {
            'creationDate': (datetime.now() - timedelta(days=1000)).isoformat()
        },
        'cert': {
            'validFrom': (datetime.now() - timedelta(days=30)).isoformat(),
            'validTo': (datetime.now() + timedelta(days=300)).isoformat(),
            'issuer': {'O': 'DigiCert Inc'}
        },
        'redirects': [],
        'patterns': [],
        'verdicts': {
            'overall': {'malicious': False},
            'engines': {'malicious': False}
        }
    }
    
    result = analyzer.calculate_threat_score(low_risk_results)
    assert result['score'] < 30
    assert result['risk_level'] == 'LOW' or result['risk_level'] == 'SAFE'
    assert len(result['recommendations']) <= 1

@pytest.mark.asyncio
async def test_scan_workflow(monkeypatch):
    """Test the complete URL scanning workflow."""
    analyzer = ThreatAnalyzer(api_key="test-api-key")
    
    # Mock response data
    mock_scan_response = {
        'uuid': 'test-uuid-123',
        'api': 'v1',
        'message': 'Submission successful'
    }
    
    mock_results = {
        'domain': {'creationDate': (datetime.now() - timedelta(days=1)).isoformat()},  # Very new domain
        'cert': {},  # Missing certificate
        'redirects': [
            'https://example.com',
            'https://bit.ly/abc123',  # URL shortener
            'http://suspicious.com',
            'http://malicious.com'    # Multiple suspicious redirects
        ],
        'patterns': [
            'login-form',
            'suspicious-redirect',
            'credential-harvest',      # Additional malicious pattern
            'data-exfil'              # Additional malicious pattern
        ],
        'verdicts': {
            'overall': {'malicious': True},
            'engines': {'malicious': True}
        }
    }
    
    # Mock the API calls
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        
        def json(self):
            return self.json_data
            
        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.exceptions.HTTPError(f"HTTP Error: {self.status_code}")
    
    def mock_post(*args, **kwargs):
        return MockResponse(mock_scan_response)
    
    def mock_get(*args, **kwargs):
        return MockResponse(mock_results)
    
    # Apply the mocks
    monkeypatch.setattr(requests, 'post', mock_post)
    monkeypatch.setattr(requests, 'get', mock_get)
    
    # Test the workflow
    scan_result = await analyzer.submit_scan("https://example.com")
    assert scan_result['uuid'] == 'test-uuid-123'
    
    results = await analyzer.get_scan_results(scan_result['uuid'])
    assert results == mock_results
    
    score_result = analyzer.calculate_threat_score(results)
    assert score_result['score'] >= 80  # High risk scenario
    assert score_result['risk_level'] == 'CRITICAL'
    assert len(score_result['recommendations']) >= 3
