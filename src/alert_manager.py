"""
Alert management module for email security notifications.
Handles alert formatting, delivery, and history tracking.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AlertManager:
    """Handles security alert generation and delivery."""
    
    def __init__(self, alert_history_path: str = 'data/alert_history.json'):
        """
        Initialize AlertManager with storage path for alert history.
        
        Args:
            alert_history_path (str): Path to store alert history
        """
        # Normalize path and ensure absolute
        self.alert_history_path = os.path.abspath(alert_history_path)
        
        # Create directory structure if it doesn't exist
        directory = os.path.dirname(self.alert_history_path)
        if directory:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {str(e)}")
                # Use current directory as fallback
                self.alert_history_path = os.path.join(os.getcwd(), os.path.basename(alert_history_path))
        
        # Load existing history if any
        self.alert_history = self._load_alert_history()
        
        # Initialize desktop notifications based on platform
        self.platform = platform.system()
        if self.platform == 'Windows':
            from win10toast import ToastNotifier
            self.toaster = ToastNotifier()
        elif self.platform == 'Darwin':  # macOS
            self.terminal_notifier = os.path.exists('/usr/local/bin/terminal-notifier')
    
    def _load_alert_history(self) -> List[Dict[str, Any]]:
        """Load alert history from file."""
        try:
            if os.path.exists(self.alert_history_path):
                with open(self.alert_history_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load alert history: {str(e)}")
        return []
    
    def _save_alert_history(self):
        """Save alert history to file."""
        try:
            with open(self.alert_history_path, 'w') as f:
                json.dump(self.alert_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save alert history: {str(e)}")
    
    def format_alert(self, threat_data: Dict[str, Any], email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format threat data into a standardized alert format.
        
        Args:
            threat_data (Dict): Threat analysis results
            email_data (Dict): Original email data
            
        Returns:
            Dict: Formatted alert data
        """
        # Extract email subject and sender
        headers = {h['name']: h['value'] for h in email_data['payload']['headers']}
        subject = headers.get('Subject', 'No Subject')
        sender = headers.get('From', 'Unknown Sender')
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'risk_level': threat_data['risk_level'],
            'threat_score': threat_data['score'],
            'url': threat_data.get('url', 'No URL available'),
            'email_info': {
                'subject': subject,
                'sender': sender,
                'received_time': headers.get('Date')
            },
            'threats': threat_data['category_scores'],
            'recommendations': threat_data['recommendations'],
            'scan_data': {
                'scan_time': threat_data['scan_time'],
                'verdicts': threat_data['verdicts']
            }
        }
        
        return alert
    
    def generate_alert_message(self, alert_data: Dict[str, Any], format: str = 'text') -> str:
        """
        Generate formatted alert message.
        
        Args:
            alert_data (Dict): Alert data to format
            format (str): Output format ('text' or 'html')
            
        Returns:
            str: Formatted alert message
        """
        if format == 'html':
            return self._generate_html_alert(alert_data)
        
        # Generate text format alert
        risk_icon = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': '📝',
            'SAFE': '✅'
        }.get(alert_data['risk_level'], '❓')

        # Create message parts
        parts = [
            f"{risk_icon} {alert_data['risk_level']} THREAT DETECTED {risk_icon}",
            f"\n📊 Threat Score: {alert_data['threat_score']}/100",
            "\n📧 Email Details:",
            f"   Subject: {alert_data['email_info']['subject']}",
            f"   From: {alert_data['email_info']['sender']}",
            f"\n🔗 URL: {alert_data.get('url', 'No URL')}",
            "\n🔍 Threat Analysis:",
        ]

        # Add threat scores
        threat_scores = [
            f"   {k.replace('_', ' ').title()}: {v:.2f}"
            for k, v in alert_data['threats'].items()
            if v > 0.3
        ]
        parts.extend(threat_scores)

        # Add recommendations
        if alert_data['recommendations']:
            parts.append("\n⚠️ Recommendations:")
            for rec in alert_data['recommendations']:
                parts.append(f"   • {rec}")

        return "\n".join(parts)
    
    def _generate_html_alert(self, alert_data: Dict[str, Any]) -> str:
        """Generate HTML formatted alert."""
        risk_colors = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffcc00',
            'LOW': '#ffff00',
            'SAFE': '#00ff00'
        }
        
        color = risk_colors.get(alert_data['risk_level'], '#808080')
        
        html = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border: 2px solid {color}; border-radius: 5px;">
            <h2 style="color: {color}; text-align: center;">
                {alert_data['risk_level']} THREAT DETECTED
            </h2>
            
            <div style="background-color: #f5f5f5; padding: 15px; border-radius: 3px; margin: 10px 0;">
                <h3>Email Details</h3>
                <p><strong>Subject:</strong> {alert_data['email_info']['subject']}</p>
                <p><strong>From:</strong> {alert_data['email_info']['sender']}</p>
                <p><strong>Threat Score:</strong> {alert_data['threat_score']}/100</p>
            </div>
            
            <div style="margin: 15px 0;">
                <h3>Threat Analysis</h3>
                <ul>
        """
        
        for category, score in alert_data['threats'].items():
            html += f"""
                    <li>{category.replace('_', ' ').title()}: {score:.2f}</li>
            """
        
        html += """
                </ul>
            </div>
        """
        
        if alert_data['recommendations']:
            html += """
            <div style="background-color: #fff3cd; padding: 15px; border-radius: 3px; margin: 10px 0;">
                <h3>Recommendations</h3>
                <ul>
            """
            
            for rec in alert_data['recommendations']:
                html += f"""
                    <li>{rec}</li>
                """
            
            html += """
                </ul>
            </div>
            """
        
        html += """
        </div>
        """
        
        return html
    
    def send_desktop_notification(self, alert_data: Dict[str, Any]):
        """
        Send desktop notification based on platform.
        
        Args:
            alert_data (Dict): Alert data to display
        """
        title = f"{alert_data['risk_level']} Security Alert"
        message = f"Suspicious email detected\nSubject: {alert_data['email_info']['subject']}\nThreat Score: {alert_data['threat_score']}/100"
        
        try:
            if self.platform == 'Windows':
                self.toaster.show_toast(
                    title,
                    message,
                    duration=10,
                    threaded=True
                )
            elif self.platform == 'Darwin' and self.terminal_notifier:
                os.system(f'terminal-notifier -title "{title}" -message "{message}"')
            elif self.platform == 'Linux':
                os.system(f'notify-send "{title}" "{message}"')
                
        except Exception as e:
            logger.error(f"Failed to send desktop notification: {str(e)}")
    
    def process_alert(self, threat_data: Dict[str, Any], email_data: Dict[str, Any]):
        """
        Process and distribute alert through all configured channels.
        
        Args:
            threat_data (Dict): Threat analysis results
            email_data (Dict): Original email data
        """
        try:
            # Format alert data
            alert_data = self.format_alert(threat_data, email_data)
            
            # Generate alert message
            message = self.generate_alert_message(alert_data)
            logger.info(message)
            
            # Send desktop notification for high-risk threats
            if alert_data['risk_level'] in ['CRITICAL', 'HIGH']:
                self.send_desktop_notification(alert_data)
            
            # Store alert in history
            self.alert_history.append(alert_data)
            self._save_alert_history()
            
        except Exception as e:
            logger.error(f"Failed to process alert: {str(e)}")
    
    def get_alert_history(self, risk_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve alert history, optionally filtered by risk level.
        
        Args:
            risk_level (str, optional): Filter by risk level
            
        Returns:
            List[Dict]: List of historical alerts
        """
        if risk_level:
            return [
                alert for alert in self.alert_history
                if alert['risk_level'] == risk_level.upper()
            ]
        return self.alert_history
