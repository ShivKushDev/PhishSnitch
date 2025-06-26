"""
Threat analysis module integrating with URLScan.io API.
Handles URL scanning, result analysis, and threat scoring.
"""

import os
import time
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    """Handles URL threat analysis using URLScan.io API."""
    
    def __init__(self, api_key: str, cache_duration: int = 3600):
        """
        Initialize ThreatAnalyzer with URLScan.io API key.
        
        Args:
            api_key (str): URLScan.io API key
            cache_duration (int): How long to cache results in seconds (default: 1 hour)
        """
        self.api_key = api_key
        self.cache_duration = cache_duration
        self.cache = {}  # Cache for scan results
        
        # API endpoints
        self.SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
        self.RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
        
        # Risk scoring weights
        self.risk_weights = {
            'domain_age': 0.25,  # Reduced slightly
            'ssl_cert': 0.15,    # Increased for certificate issues
            'malicious_patterns': 0.25,  # Increased for suspicious patterns
            'redirect_chain': 0.1,
            'security_checks': 0.25  # Balanced with other critical factors
        }
    
    def _cache_key(self, url: str) -> str:
        """Generate cache key for URL."""
        return hashlib.sha256(url.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_time: float) -> bool:
        """Check if cached result is still valid."""
        return time.time() - cache_time < self.cache_duration
    
    async def submit_scan(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning to URLScan.io.
        
        Args:
            url (str): URL to scan
            
        Returns:
            Dict: Scan submission result including UUID
        """
        headers = {
            'API-Key': self.api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'PhishSnitch Security Scanner'
        }
        
        data = {
            'url': url,
            'visibility': 'public',  # Using public visibility as per docs
            'tags': ['PhishSnitch', 'automated-scan'],
            'customagent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/98.0.4758.102'
        }
        
        try:
            response = requests.post(
                self.SUBMIT_URL,
                headers=headers,
                json=data,
                timeout=30  # Adding timeout
            )
            
            if response.status_code == 429:  # Rate limit hit
                retry_after = int(response.headers.get('X-Rate-Limit-Reset-After', 60))
                logger.warning(f"Rate limit hit, waiting {retry_after} seconds")
                await asyncio.sleep(retry_after)
                return await self.submit_scan(url)  # Retry after waiting
                
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Scan submission failed for {url}"
            if hasattr(e.response, 'json'):
                try:
                    error_details = e.response.json()
                    error_msg += f": {error_details.get('message', str(e))}"
                except:
                    error_msg += f": {str(e)}"
            logger.error(error_msg)
            raise
    
    async def get_scan_results(self, scan_uuid: str, max_retries: int = 10) -> Optional[Dict[str, Any]]:
        """
        Retrieve scan results from URLScan.io.
        
        Args:
            scan_uuid (str): UUID of the scan
            max_retries (int): Maximum number of retry attempts
            
        Returns:
            Dict: Scan results or None if unavailable
        """
        headers = {
            'API-Key': self.api_key
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    self.RESULT_URL.format(uuid=scan_uuid),
                    headers=headers
                )
                
                if response.status_code == 404:
                    # Results not ready, wait and retry
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
                
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to retrieve results for scan {scan_uuid}: {str(e)}")
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)
        
        return None
    
    def analyze_domain_age(self, domain_data: Dict[str, Any]) -> float:
        """Calculate risk score based on domain age."""
        try:
            creation_date = datetime.fromisoformat(domain_data.get('creationDate', ''))
            age_days = (datetime.now() - creation_date).days
            
            if age_days < 7:
                return 1.0  # Highest risk for very new domains
            elif age_days < 30:
                return 0.7
            elif age_days < 90:
                return 0.4
            elif age_days < 365:
                return 0.2
            else:
                return 0.0
                
        except (ValueError, TypeError):
            return 0.5  # Default score if age cannot be determined
    
    def analyze_ssl_cert(self, cert_data: Dict[str, Any]) -> float:
        """Calculate risk score based on SSL certificate."""
        risk_score = 0.0
        
        if not cert_data:
            return 1.0  # No SSL certificate is highest risk
        
        # Check certificate validity
        try:
            valid_from = datetime.fromisoformat(cert_data.get('validFrom', ''))
            valid_to = datetime.fromisoformat(cert_data.get('validTo', ''))
            now = datetime.now()
            
            if now < valid_from or now > valid_to:
                risk_score += 0.5
            
            # Check if cert is about to expire
            if valid_to - now < timedelta(days=30):
                risk_score += 0.3
                
        except (ValueError, TypeError):
            risk_score += 0.4
        
        # Check certificate issuer
        issuer = cert_data.get('issuer', {})
        if not any(trusted in issuer.get('O', '').lower() for trusted in ['digicert', 'let\'s encrypt', 'comodo']):
            risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def analyze_redirect_chain(self, redirects: List[str]) -> float:
        """Calculate risk score based on redirect chain."""
        if not redirects:
            return 0.0
        
        risk_score = 0.0
        
        # Check number of redirects
        num_redirects = len(redirects)
        if num_redirects > 5:
            risk_score += 0.5
        elif num_redirects > 3:
            risk_score += 0.3
        
        # Check for suspicious redirect patterns
        for url in redirects:
            parsed = urlparse(url)
            if any(service in parsed.netloc for service in ['bit.ly', 'tinyurl.com', 't.co']):
                risk_score += 0.2
            if not parsed.scheme == 'https':
                risk_score += 0.2
        
        return min(risk_score, 1.0)
    
    def calculate_threat_score(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall threat score from scan results.
        
        Args:
            scan_results (Dict): Raw scan results from URLScan.io
            
        Returns:
            Dict: Threat analysis including score and reasons
        """
        scores = {
            'domain_age': self.analyze_domain_age(scan_results.get('domain', {})),
            'ssl_cert': self.analyze_ssl_cert(scan_results.get('cert', {})),
            'redirect_chain': self.analyze_redirect_chain(scan_results.get('redirects', [])),
            'malicious_patterns': 0.0,  # Will be set based on patterns
            'security_checks': 0.0  # Will be set based on security verdicts
        }
        
        # Enhanced pattern scoring
        patterns = scan_results.get('patterns', [])
        if patterns:
            # More weight for critical patterns
            critical_patterns = {'credential-harvest', 'data-exfil', 'malware-download'}
            pattern_weights = sum(0.4 if p in critical_patterns else 0.2 for p in patterns)
            scores['malicious_patterns'] = min(pattern_weights, 1.0)
        
        # Enhanced security verdict scoring
        verdicts = scan_results.get('verdicts', {})
        if verdicts.get('overall', {}).get('malicious'):
            scores['security_checks'] = 1.0
            # Add extra weight for confirmed malicious
            scores['malicious_patterns'] = max(scores['malicious_patterns'], 0.8)
        elif verdicts.get('engines', {}).get('malicious'):
            scores['security_checks'] = 0.8
        
        # Calculate weighted average
        total_score = sum(
            score * self.risk_weights[category]
            for category, score in scores.items()
        )
        
        return {
            'score': round(total_score * 100),  # Convert to 0-100 scale
            'risk_level': self._get_risk_level(total_score),
            'category_scores': scores,
            'verdicts': scan_results.get('verdicts', {}),
            'scan_time': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(scores)
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Convert numerical score to risk level category."""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        elif score >= 0.2:
            return 'LOW'
        else:
            return 'SAFE'
    
    def _generate_recommendations(self, scores: Dict[str, float]) -> List[str]:
        """Generate security recommendations based on risk scores."""
        recommendations = []
        
        if scores['domain_age'] > 0.5:
            recommendations.append(
                "Recently registered domain detected. Exercise extreme caution."
            )
        
        if scores['ssl_cert'] > 0.5:
            recommendations.append(
                "SSL certificate issues detected. Verify website legitimacy."
            )
        
        if scores['redirect_chain'] > 0.3:
            recommendations.append(
                "Multiple redirects detected. Check final destination carefully."
            )
        
        if scores['malicious_patterns'] > 0.3:
            recommendations.append(
                "Suspicious patterns detected. Avoid entering sensitive information."
            )
        
        if scores['security_checks'] > 0.5:
            recommendations.append(
                "Security checks indicate potential threats. Do not proceed."
            )
        
        return recommendations
