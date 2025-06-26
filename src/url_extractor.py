"""
URL extraction and preprocessing module.
Handles URL normalization, deduplication, and preliminary analysis.
"""

import re
from urllib.parse import urlparse, urljoin, unquote
from typing import List, Set, Dict, Tuple, Any
import logging
import requests
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class URLExtractor:
    """Handles URL extraction, normalization, and preprocessing."""
    
    def __init__(self, whitelist: List[str] = None, blacklist: List[str] = None):
        """
        Initialize URLExtractor with optional whitelist and blacklist.
        
        Args:
            whitelist (List[str]): List of whitelisted domains
            blacklist (List[str]): List of blacklisted domains
        """
        self.whitelist = set(whitelist) if whitelist else set()
        self.blacklist = set(blacklist) if blacklist else set()
        self.url_cache = {}  # Cache for resolved URLs
        
        # Common URL shortening services
        self.shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'shorte.st'
        }
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL by standardizing format and decoding.
        
        Args:
            url (str): URL to normalize
            
        Returns:
            str: Normalized URL
        """
        try:
            # Handle empty or invalid URLs
            if not url:
                return url
                
            # Decode URL-encoded characters and strip whitespace
            url = unquote(url).strip()
            
            # Handle protocol-relative URLs
            if url.startswith('//'):
                url = 'http:' + url
            
            # Parse URL
            parsed = urlparse(url)
            
            # If no scheme and netloc, treat path as netloc
            if not parsed.scheme and not parsed.netloc:
                # Check if path contains domain and additional path
                parts = parsed.path.split('/', 1)
                domain = parts[0]
                path = '/' + parts[1] if len(parts) > 1 else ''
                
                # Create new URL with proper structure
                url = f'http://{domain}{path}'
                if parsed.query:
                    url += f'?{parsed.query}'
                if parsed.fragment:
                    url += f'#{parsed.fragment}'
                parsed = urlparse(url)
            elif not parsed.scheme:
                # If just missing scheme, add http://
                url = 'http://' + url
                parsed = urlparse(url)
            
            # Convert to lowercase
            normalized = parsed.scheme.lower() + '://' + parsed.netloc.lower()
            
            # Normalize path
            if parsed.path:
                # Split path into components and filter out '.' and empty parts
                path_parts = [p for p in parsed.path.split('/') if p and p != '.']
                
                # Handle '..' parts properly
                normalized_parts = []
                for part in path_parts:
                    if part == '..':
                        if normalized_parts:
                            normalized_parts.pop()
                    else:
                        normalized_parts.append(part.lower())  # Convert path parts to lowercase
                
                # Reconstruct path
                if normalized_parts:
                    normalized += '/' + '/'.join(normalized_parts)
                elif parsed.path.startswith('/'):
                    normalized += '/'
            
            # Add query parameters if present
            if parsed.query:
                # Sort query parameters for consistency
                params = sorted(parsed.query.split('&'))
                normalized += '?' + '&'.join(params)
            
            # Add fragment if present
            if parsed.fragment:
                normalized += '#' + parsed.fragment.lower()
                
            return normalized
            
        except Exception as e:
            logger.error(f"URL normalization failed for {url}: {str(e)}")
            return url
    
    def extract_domain(self, url: str) -> str:
        """
        Extract domain from URL.
        
        Args:
            url (str): URL to extract domain from
            
        Returns:
            str: Domain name
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception as e:
            logger.error(f"Domain extraction failed for {url}: {str(e)}")
            return ""
    
    def is_domain_safe(self, domain: str) -> bool:
        """
        Check if domain is in whitelist or blacklist.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if domain is safe, False if blacklisted, None if unknown
        """
        if domain in self.whitelist:
            return True
        if domain in self.blacklist:
            return False
        return None
    
    def is_shortened_url(self, url: str) -> bool:
        """
        Check if URL is from a known URL shortening service.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if URL is shortened
        """
        domain = self.extract_domain(url)
        return domain in self.shorteners
    
    def resolve_shortened_url(self, url: str, timeout: int = 5) -> str:
        """
        Safely resolve shortened URLs by following redirects.
        
        Args:
            url (str): Shortened URL to resolve
            timeout (int): Request timeout in seconds
            
        Returns:
            str: Resolved URL or original if resolution fails
        """
        try:
            if url in self.url_cache:
                return self.url_cache[url]
            
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            resolved_url = response.url
            self.url_cache[url] = resolved_url
            return resolved_url
            
        except RequestException as e:
            logger.warning(f"Failed to resolve shortened URL {url}: {str(e)}")
            return url
    
    def process_urls(self, urls: List[str], max_workers: int = 5) -> Dict[str, str]:
        """
        Process list of URLs: normalize, deduplicate, and resolve shortened URLs.
        
        Args:
            urls (List[str]): List of URLs to process
            max_workers (int): Maximum number of concurrent workers
            
        Returns:
            Dict[str, str]: Mapping of original URLs to processed URLs
        """
        # Normalize and deduplicate URLs
        unique_urls = {url: self.normalize_url(url) for url in urls}
        
        # Find shortened URLs
        shortened_urls = [
            url for url in unique_urls.values()
            if self.is_shortened_url(url)
        ]
        
        # Resolve shortened URLs concurrently
        resolved_urls = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.resolve_shortened_url, url): url
                for url in shortened_urls
            }
            
            for future in future_to_url:
                url = future_to_url[future]
                try:
                    resolved_urls[url] = future.result()
                except Exception as e:
                    logger.error(f"Failed to resolve URL {url}: {str(e)}")
                    resolved_urls[url] = url
        
        # Update URL mapping with resolved URLs
        processed_urls = {}
        for original, normalized in unique_urls.items():
            if normalized in resolved_urls:
                processed_urls[original] = resolved_urls[normalized]
            else:
                processed_urls[original] = normalized
        
        return processed_urls

    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL structure for potential suspicious patterns.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Dict: Analysis results
        """
        try:
            parsed = urlparse(url)
            analysis = {
                'domain': parsed.netloc,
                'path_depth': len([p for p in parsed.path.split('/') if p]),
                'query_params': len(parsed.query.split('&')) if parsed.query else 0,
                'uses_https': parsed.scheme == 'https',
                'suspicious_patterns': []
            }
            
            # Check for suspicious patterns
            patterns = [
                (r'paypal.*\.(?!paypal\.com)', 'Potential PayPal phishing'),
                (r'verify.*account', 'Account verification request'),
                (r'secur.*\.(?!trusted\.com)', 'Security-themed domain'),
                (r'login.*\.(?!trusted\.com)', 'Login-themed domain'),
                (r'[0-9]{8,}', 'Long numeric sequence'),
                (r'[a-zA-Z0-9]{25,}', 'Unusually long random string')
            ]
            
            for pattern, description in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    analysis['suspicious_patterns'].append(description)
            
            return analysis
            
        except Exception as e:
            logger.error(f"URL analysis failed for {url}: {str(e)}")
            return {'error': str(e)}
