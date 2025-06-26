"""
Gmail API integration and email monitoring module.
Handles email polling, filtering, and URL extraction.
"""

import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Any
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EmailMonitor:
    """Handles Gmail API integration and email monitoring."""
    
    # Gmail API scopes required for the application
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self, credentials_path: str):
        """
        Initialize the EmailMonitor with Gmail API credentials.
        
        Args:
            credentials_path (str): Path to the Gmail API credentials file
        """
        self.credentials_path = credentials_path
        self.creds = None
        self.service = None
    
    def authenticate(self) -> bool:
        """
        Authenticate with Gmail API using OAuth2.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            if os.path.exists('token.json'):
                self.creds = Credentials.from_authorized_user_file('token.json', self.SCOPES)
            
            if not self.creds or not self.creds.valid:
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    self.creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_path, self.SCOPES)
                    self.creds = flow.run_local_server(port=0)
                
                with open('token.json', 'w') as token:
                    token.write(self.creds.to_json())
            
            self.service = build('gmail', 'v1', credentials=self.creds)
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def get_unread_emails(self, max_results: int = 10) -> List[Dict[str, Any]]:
        """
        Fetch unread emails from Gmail.
        
        Args:
            max_results (int): Maximum number of emails to fetch
            
        Returns:
            List[Dict]: List of email data dictionaries
        """
        try:
            results = self.service.users().messages().list(
                userId='me',
                labelIds=['UNREAD'],
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for message in messages:
                email_data = self.service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='full'
                ).execute()
                
                emails.append(email_data)
            
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch emails: {str(e)}")
            return []
    
    def extract_urls(self, email_data: Dict[str, Any]) -> List[str]:
        """
        Extract URLs from email content.
        
        Args:
            email_data (Dict): Email data from Gmail API
            
        Returns:
            List[str]: List of extracted URLs
        """
        urls = set()
        
        try:
            # Get email body
            if 'payload' not in email_data:
                return list(urls)
                
            payload = email_data['payload']
            if 'parts' in payload:
                parts = payload['parts']
            else:
                parts = [payload]
            
            for part in parts:
                if part.get('mimeType') == 'text/html':
                    data = base64.urlsafe_b64decode(part['body']['data']).decode()
                    # Parse HTML and extract links
                    soup = BeautifulSoup(data, 'html.parser')
                    for link in soup.find_all('a'):
                        href = link.get('href')
                        if href:
                            urls.add(href)
                elif part.get('mimeType') == 'text/plain':
                    data = base64.urlsafe_b64decode(part['body']['data']).decode()
                    # Extract URLs using regex
                    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
                    found_urls = re.findall(url_pattern, data)
                    urls.update(found_urls)
            
            return list(urls)
            
        except Exception as e:
            logger.error(f"Failed to extract URLs: {str(e)}")
            return list(urls)
