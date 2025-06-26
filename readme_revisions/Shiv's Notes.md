# PhishSnitch: How It Works

## Overview
PhishSnitch is an email security tool that automatically analyzes incoming emails for potential phishing threats. It monitors your Gmail inbox, extracts URLs from emails, analyzes them using URLScan.io, and alerts you about any suspicious content.

## Core Components

### 1. src/app.py (Main Application)
- **Purpose**: Controls the entire application flow
- **Key Functions**:
  - Initializes all components
  - Monitors emails in real-time
  - Coordinates between different modules
  - Handles configuration and setup

### 2. src/email_monitor.py (Email Handler)
- **Purpose**: Interfaces with Gmail API
- **Functions**:
  - Authenticates with Gmail
  - Retrieves unread emails
  - Extracts URLs from email content
  - Uses Gmail API credentials from config/credentials.json

### 3. src/url_extractor.py (URL Processor)
- **Purpose**: Handles URL processing and normalization
- **Functions**:
  - Normalizes URLs (fixes formatting)
  - Removes duplicates
  - Resolves shortened URLs
  - Checks against whitelist/blacklist
- **Example**: Converts "EXAMPLE.COM/path" to "http://example.com/path"

### 4. src/threat_analyzer.py (Security Analysis)
- **Purpose**: Analyzes URLs for threats using URLScan.io API
- **How Scoring Works**:
  1. Submits URL to URLScan.io
  2. Analyzes multiple factors:
     - Domain age (25% weight)
     - SSL certificate (15% weight)
     - Malicious patterns (25% weight)
     - Redirect chain (10% weight)
     - Security checks (25% weight)
  3. Calculates final score (0-100)
  4. Determines risk level:
     - 80-100: CRITICAL
     - 60-79: HIGH
     - 40-59: MEDIUM
     - 20-39: LOW
     - 0-19: SAFE

### 5. src/alert_manager.py (Notification System)
- **Purpose**: Handles alerts and notifications
- **Functions**:
  - Formats alert messages
  - Sends desktop notifications
  - Maintains alert history
  - Stores alerts in data/alert_history.json

## How URLs Are Scored

1. **Initial Check**
   - Domain age (newer domains = higher risk)
   - SSL certificate validity
   - Number of redirects

2. **Pattern Analysis**
   - Checks for phishing indicators
   - Suspicious keywords
   - Unusual URL patterns

3. **Security Verdicts**
   - URLScan.io engine results
   - Malicious content detection
   - Security flags

4. **Final Score Calculation**
```python
total_score = (
    (domain_age * 0.25) +
    (ssl_cert * 0.15) +
    (malicious_patterns * 0.25) +
    (redirect_chain * 0.10) +
    (security_checks * 0.25)
) * 100
```

## Program Flow
1. **Startup**
   - Loads config.yaml
   - Authenticates with Gmail
   - Creates necessary directories

2. **Monitoring Loop**
   - Checks for new emails every X minutes
   - Extracts URLs from new emails
   - Processes each URL

3. **URL Analysis**
   - Normalizes URLs
   - Submits to URLScan.io
   - Waits for analysis results
   - Calculates threat score

4. **Alert Generation**
   - Creates formatted alert
   - Logs results
   - Sends notifications if high risk
   - Saves to history

## API Integration (URLScan.io)

### How the API Works
1. **Submission**
   ```json
   POST https://urlscan.io/api/v1/scan/
   Headers: {
     "API-Key": "your-key",
     "Content-Type": "application/json"
   }
   Body: {
     "url": "http://example.com",
     "visibility": "public"
   }
   ```

2. **Results**
   - API returns a scan UUID
   - Wait for scan completion
   - Fetch results using UUID
   - Parse and analyze data

### Rate Limits
- Per minute limit
- Per hour limit
- Per day limit
- Error handling with retry logic

## Configuration (config/config.yaml)
- Gmail API credentials path
- URLScan.io API key
- Check intervals
- Risk thresholds
- Notification settings
- Whitelist/Blacklist domains

## Best Practices for Use
1. Set appropriate check intervals
2. Keep API keys secure
3. Monitor logs for issues
4. Update whitelists regularly
5. Review alert history periodically

## Presentation Guide

### Key Points to Cover
1. **Problem Statement**
   - Rise in phishing attacks
   - Need for automated detection
   - Challenge of real-time monitoring

2. **Solution Architecture**
   - Email monitoring system
   - URL analysis pipeline
   - Threat scoring mechanism
   - Alert management system

3. **Technical Highlights**
   - API integrations (Gmail + URLScan.io)
   - Async processing for performance
   - Modular design for extensibility
   - Comprehensive scoring system

4. **Demo Scenarios**
   - Regular email processing
   - Phishing attempt detection
   - Alert generation
   - Threat score explanation

### Google Cloud Deployment

1. **Required Services**
   - Cloud Functions (for processing)
   - Cloud Storage (for logs/history)
   - Cloud Pub/Sub (for notifications)
   - Cloud Scheduler (for timing)

2. **Setup Steps**
   ```bash
   # Create Cloud Function
   gcloud functions deploy phish-snitch \
     --runtime python39 \
     --trigger-http \
     --env-vars-file .env.yaml

   # Set up Cloud Storage
   gsutil mb gs://phish-snitch-storage

   # Create Pub/Sub topic
   gcloud pubsub topics create phish-alerts
   ```

3. **Monitoring**
   - Cloud Monitoring for metrics
   - Cloud Logging for debugging
   - Error reporting setup
   - Performance tracking

4. **Security**
   - IAM roles and permissions
   - API key management
   - Secure storage handling
   - Network security

5. **Scaling Considerations**
   - Rate limiting handling
   - Resource allocation
   - Cost optimization
   - Performance tuning

## Troubleshooting Tips
1. Check logs in logs/app.log
2. Verify API keys in config.yaml
3. Monitor rate limits
4. Review alert_history.json
5. Check Gmail API quotas

## Future Enhancements
1. Machine learning for threat detection
2. Additional API integrations
3. Custom scoring rules
4. Advanced reporting features
5. Team collaboration features
