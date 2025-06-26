"""Unit tests for URL extraction and processing functionality."""

import pytest
from src.url_extractor import URLExtractor

@pytest.fixture
def url_extractor():
    """Create URLExtractor instance with test configuration."""
    whitelist = ['trusted-domain.com']
    blacklist = ['malicious-domain.com']
    return URLExtractor(whitelist=whitelist, blacklist=blacklist)

def test_normalize_url():
    """Test URL normalization functionality."""
    extractor = URLExtractor()
    
    # Test cases
    test_cases = [
        ('HTTP://EXAMPLE.COM', 'http://example.com'),
        ('example.com', 'http://example.com'),
        ('https://sub.example.com/path?q=1', 'https://sub.example.com/path?q=1'),
        ('https://example.com/Path/../file.html', 'https://example.com/file.html'),
        ('http://Example.COM/path', 'http://example.com/path'),
        ('//example.com', 'http://example.com'),
        ('example.com/path', 'http://example.com/path'),
    ]
    
    for input_url, expected in test_cases:
        normalized = extractor.normalize_url(input_url)
        assert normalized == expected, f"URL: {input_url}\nExpected: {expected}\nGot: {normalized}"

def test_extract_domain():
    """Test domain extraction functionality."""
    extractor = URLExtractor()
    
    # Test cases
    assert extractor.extract_domain('https://example.com/path') == 'example.com'
    assert extractor.extract_domain('http://sub.example.com') == 'sub.example.com'
    assert extractor.extract_domain('https://example.co.uk/path?q=1') == 'example.co.uk'

def test_is_domain_safe():
    """Test domain safety checking functionality."""
    extractor = URLExtractor(
        whitelist=['safe.com', 'trusted.com'],
        blacklist=['malicious.com', 'phishing.com']
    )
    
    # Test cases
    assert extractor.is_domain_safe('safe.com') is True
    assert extractor.is_domain_safe('trusted.com') is True
    assert extractor.is_domain_safe('malicious.com') is False
    assert extractor.is_domain_safe('phishing.com') is False
    assert extractor.is_domain_safe('unknown.com') is None

def test_is_shortened_url():
    """Test shortened URL detection."""
    extractor = URLExtractor()
    
    # Test cases
    assert extractor.is_shortened_url('https://bit.ly/abc123') is True
    assert extractor.is_shortened_url('https://t.co/xyz789') is True
    assert extractor.is_shortened_url('https://example.com/page') is False

def test_process_urls():
    """Test URL processing pipeline."""
    extractor = URLExtractor()
    
    test_urls = [
        'https://example.com/page',
        'http://EXAMPLE.COM/other-page',
        'example.org/path',
        'https://example.com/page'  # Duplicate
    ]
    
    processed = extractor.process_urls(test_urls)
    
    # Verify results
    assert len(processed) == 3  # Should deduplicate
    assert all(url.startswith(('http://', 'https://')) for url in processed.values())
    assert any('example.com/page' in url for url in processed.values())
