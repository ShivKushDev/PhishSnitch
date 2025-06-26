"""
Main application module for Email Threat Analyzer.
Coordinates email monitoring, threat analysis, and alerting.
"""

import os
import json
import logging
import asyncio
from typing import Dict, Any, List
import yaml
from datetime import datetime, timedelta

from email_monitor import EmailMonitor
from url_extractor import URLExtractor
from threat_analyzer import ThreatAnalyzer
from alert_manager import AlertManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EmailThreatAnalyzer:
    """Main application class coordinating all components."""
    
    def __init__(self, config_path: str = 'config/config.yaml'):
        """
        Initialize the Email Threat Analyzer.
        
        Args:
            config_path (str): Path to configuration file
        """
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.email_monitor = EmailMonitor(
            credentials_path=self.config['gmail']['credentials_path']
        )
        
        self.url_extractor = URLExtractor(
            whitelist=self.config['security']['whitelist'],
            blacklist=self.config['security']['blacklist']
        )
        
        self.threat_analyzer = ThreatAnalyzer(
            api_key=self.config['urlscan']['api_key']
        )
        
        self.alert_manager = AlertManager(
            alert_history_path=self.config['alerts']['history_path']
        )
        
        # Track last check time
        self.last_check = datetime.now() - timedelta(minutes=30)
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            # Ensure config directory exists
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # Create default config if it doesn't exist
            if not os.path.exists(config_path):
                default_config = {
                    'gmail': {
                        'credentials_path': 'config/credentials.json',
                        'check_interval': 300  # 5 minutes
                    },
                    'urlscan': {
                        'api_key': '',  # To be filled by user
                        'cache_duration': 3600  # 1 hour
                    },
                    'security': {
                        'whitelist': [],
                        'blacklist': [],
                        'risk_threshold': 70  # Minimum score for high-risk alerts
                    },
                    'alerts': {
                        'history_path': 'data/alert_history.json',
                        'desktop_notifications': True
                    }
                }
                
                with open(config_path, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                
                logger.info(f"Created default configuration at {config_path}")
                return default_config
            
            # Load existing config
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            return config
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {str(e)}")
            raise
    
    async def setup(self) -> bool:
        """
        Perform initial setup and authentication.
        
        Returns:
            bool: True if setup successful
        """
        try:
            # Create necessary directories
            os.makedirs('logs', exist_ok=True)
            os.makedirs('data', exist_ok=True)
            
            # Authenticate with Gmail
            if not self.email_monitor.authenticate():
                logger.error("Failed to authenticate with Gmail")
                return False
            
            logger.info("Setup completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Setup failed: {str(e)}")
            return False
    
    async def process_email(self, email_data: Dict[str, Any]):
        """
        Process a single email for threats.
        
        Args:
            email_data (Dict): Email data from Gmail API
        """
        try:
            # Extract URLs from email
            urls = self.email_monitor.extract_urls(email_data)
            if not urls:
                return
            
            # Process and normalize URLs
            processed_urls = self.url_extractor.process_urls(urls)
            
            # Analyze each unique URL
            for original_url, processed_url in processed_urls.items():
                # Submit URL for scanning
                scan_data = await self.threat_analyzer.submit_scan(processed_url)
                
                # Wait for and retrieve scan results
                if scan_data and 'uuid' in scan_data:
                    scan_results = await self.threat_analyzer.get_scan_results(scan_data['uuid'])
                    
                    if scan_results:
                        # Calculate threat score and analyze results
                        threat_data = self.threat_analyzer.calculate_threat_score(scan_results)
                        
                        # Add URL to threat data
                        threat_data['url'] = original_url
                        
                        # Always process alert to show score, regardless of threshold
                        self.alert_manager.process_alert(threat_data, email_data)
                        
                        # Log the analysis
                        logger.info(f"Analyzed URL: {original_url}")
                        logger.info(f"Threat Score: {threat_data['score']}/100")
                
        except Exception as e:
            logger.error(f"Failed to process email: {str(e)}")
    
    async def check_new_emails(self):
        """Check for and process new emails."""
        try:
            # Get unread emails
            emails = self.email_monitor.get_unread_emails()
            
            if emails:
                logger.info(f"Processing {len(emails)} new emails")
                
                # Process each email
                for email in emails:
                    await self.process_email(email)
            
            self.last_check = datetime.now()
            
        except Exception as e:
            logger.error(f"Failed to check new emails: {str(e)}")
    
    async def run(self):
        """Main execution loop."""
        try:
            # Perform initial setup
            if not await self.setup():
                logger.error("Failed to setup application")
                return
            
            logger.info("Starting Email Threat Analyzer")
            
            while True:
                await self.check_new_emails()
                
                # Wait for next check interval
                check_interval = self.config['gmail']['check_interval']
                await asyncio.sleep(check_interval)
                
        except KeyboardInterrupt:
            logger.info("Shutting down Email Threat Analyzer")
        except Exception as e:
            logger.error(f"Application error: {str(e)}")

def main():
    """Application entry point."""
    app = EmailThreatAnalyzer()
    asyncio.run(app.run())

if __name__ == '__main__':
    main()
