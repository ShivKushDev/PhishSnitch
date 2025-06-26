# PhishSnitch: Email Threat Analyzer

PhishSnitch is a sophisticated email security tool that automatically monitors your Gmail inbox for potentially malicious URLs and alerts you to possible phishing attempts or security threats.

## Features

- **Real-time Email Monitoring**: Continuously monitors your Gmail inbox for new emails
- **Advanced URL Analysis**: 
  - Extracts and normalizes URLs from both HTML and plain text emails
  - Resolves shortened URLs to reveal true destinations
  - Handles URL redirects safely
- **Comprehensive Threat Detection**:
  - Integrates with URLScan.io for deep URL analysis
  - Checks domain age and reputation
  - Analyzes SSL certificates
  - Detects suspicious redirect chains
  - Identifies potential phishing patterns
- **Smart Alerting**:
  - Desktop notifications for high-risk threats
  - Detailed HTML and text-based reports
  - Customizable alert thresholds
  - Alert history tracking
- **Security Features**:
  - Domain whitelist/blacklist support
  - Secure credential management
  - Rate limiting and API quota management
  - Safe URL handling

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ShivKushDev/PhishSnitch.git
   cd PhishSnitch
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Platform-specific requirements:
   - **Windows**: No additional steps needed
   - **macOS**: Install terminal-notifier:
     ```bash
     brew install terminal-notifier
     ```
   - **Linux**: Ensure libnotify is installed:
     ```bash
     sudo apt-get install libnotify-bin
     ```

## Configuration

1. Set up Google Cloud Project:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Create a new project
   - Enable the Gmail API
   - Create OAuth 2.0 credentials:
     1. Go to "Credentials" page
     2. Click "Create Credentials" and select "OAuth client ID"
     3. Application type: "Desktop application"
     4. Name: "PhishSnitch Email Monitor"
     5. Click "Create"
   - Download the credentials file as `credentials.json`

   Note: When first running the application, it will open a browser window asking you to authorize access to your Gmail account. This is normal and required for the application to monitor your inbox.

2. Get URLScan.io API key:
   - Sign up at [URLScan.io](https://urlscan.io)
   - Get your API key from the user settings

3. Configure the application:
   1. Create a config directory in your PhishSnitch project folder:
      ```bash
      mkdir config
      ```
   
   2. Move your downloaded credentials file:
      - After downloading credentials.json from Google Cloud Console
      - Move it to the `config` directory in your project:
        ```bash
        mv /path/to/downloaded/credentials.json config/credentials.json
        ```
      - If you downloaded it elsewhere, copy it to: `PhishSnitch/config/credentials.json`
   
   3. Create and edit `config/config.yaml`:
     ```yaml
     gmail:
       credentials_path: config/credentials.json
       check_interval: 300  # 5 minutes

     urlscan:
       api_key: "your-urlscan-api-key"
       cache_duration: 3600  # 1 hour

     security:
       whitelist: []  # Trusted domains
       blacklist: []  # Known malicious domains
       risk_threshold: 70  # Minimum score for high-risk alerts

     alerts:
       history_path: data/alert_history.json
       desktop_notifications: true
     ```

## Usage

1. Start the application:
   ```bash
   python src/app.py
   ```

2. First-time setup:
   - The application will open your browser for Gmail authentication
   - Grant the required permissions
   - The authentication token will be saved for future use

3. Monitor the alerts:
   - Desktop notifications will appear for high-risk threats
   - Check the logs for detailed information:
     ```bash
     tail -f logs/app.log
     ```
   - View alert history in `data/alert_history.json`

## Alert Levels

- **CRITICAL** (Score: 80-100)
  - Recently registered domains (<7 days)
  - Multiple suspicious indicators
  - Known malicious patterns
  - Credential harvesting detected

- **HIGH** (Score: 60-79)
  - New domains (<30 days)
  - Suspicious redirects
  - SSL certificate issues
  - Unusual patterns

- **MEDIUM** (Score: 40-59)
  - Multiple redirects
  - Mixed content
  - Minor suspicions

- **LOW** (Score: 20-39)
  - New but legitimate domains
  - Non-HTTPS content
  - URL shorteners

## Testing Guide

### Safe Testing Environment
To safely test PhishSnitch without creating actual malicious content:

1. **Create a Test Gmail Account**
   - Create a separate Gmail account for testing
   - This keeps testing separate from your primary email

2. **Sample Test Scenarios**
   - Send test emails to yourself with these safe patterns:
     ```
     Subject: "Verify your account now"
     From: "security@bank-verify.example.com"
     Content: "Click here to verify: http://suspicious-example.com/login"
     ```

3. **URL Patterns to Test**
   - URL shorteners: bit.ly, tinyurl.com
   - Suspicious domains: "secure-bank-verify.example.com"
   - Mixed HTTP/HTTPS: "http://login.example.com"
   - Multiple redirects: Using URL shorteners in chain

4. **Test Email Templates**
   ```
   Template 1 (Banking Simulation):
   Subject: Urgent: Verify Your Account
   Content: Dear customer, your account needs verification.
   Link: http://bank-secure-verify.example.com

   Template 2 (Login Page):
   Subject: Reset Your Password
   Content: Click here to reset your credentials
   Link: http://accounts-verify.example.com/login

   Template 3 (Multiple URLs):
   Subject: Updated Documents
   Content: Review these documents
   Links: https://bit.ly/test123, http://file-share.example.com
   ```

5. **Testing Risk Levels**
   - Low Risk: Use established domains, HTTPS
   - Medium Risk: URL shorteners, mixed content
   - High Risk: New domains, suspicious patterns
   - Critical: Multiple red flags, credential harvesting

### Safe URLs for Testing
Use these safe domains that trigger detection but aren't harmful:
- example.com (standard test domain)
- test-phishing.example.com
- suspicious-test.example.com

### Running Tests

1. Install test dependencies:
   ```bash
   pip install pytest pytest-cov pytest-asyncio
   ```

2. Add the project root to PYTHONPATH:
   - **Windows (PowerShell)**:
     ```powershell
     $env:PYTHONPATH = "$PWD"
     ```
   - **Windows (CMD)**:
     ```cmd
     set PYTHONPATH=%CD%
     ```
   - **Linux/macOS**:
     ```bash
     export PYTHONPATH=$PWD
     ```

3. Run tests using python -m pytest:
   ```bash
   # Basic test run
   python -m pytest tests/

   # With verbose output
   python -m pytest -v tests/

   # With coverage report
   python -m pytest --cov=src tests/
   ```

4. Manual Testing Process:
   - Send test email to your test Gmail account
   - Run PhishSnitch: `python src/app.py`
   - Check notifications and logs
   - Verify alert history in data/alert_history.json

IMPORTANT: Never create or distribute actual malicious content. Always use example.com or your own controlled test domains for testing.

## Development

1. Set up development environment:
   ```bash
   pip install -r requirements.txt
   ```

2. Run tests:
   ```bash
   pytest tests/
   ```

3. Code formatting:
   ```bash
   black src/
   ```

4. Type checking:
   ```bash
   mypy src/
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to URLScan.io for their excellent API
- Google Gmail API team for comprehensive documentation
- All contributors and users of the project

## Learning Resources

### Video Tutorials

1. **Gmail API Integration**
   - [Google Gmail API Python Tutorial](https://www.youtube.com/watch?v=7qym2BO_MzM) - Learn how to set up and use the Gmail API
   - [OAuth 2.0 for Google APIs](https://www.youtube.com/watch?v=hfWe1gPCnzc) - Understanding authentication

2. **Web Security & URL Analysis**
   - [Web Security Testing with Python](https://www.youtube.com/watch?v=cb9Sf8ZZX8U) - Learn about URL analysis and security testing
   - [Understanding SSL/TLS Certificates](https://www.youtube.com/watch?v=T4Df5_cojAs) - Deep dive into SSL certificate verification

3. **Python Programming Concepts**
   - [Async/Await in Python](https://www.youtube.com/watch?v=t5Bo1Je9EmE) - Understanding asynchronous programming
   - [Working with APIs in Python](https://www.youtube.com/watch?v=tb8gHvYlCFs) - API integration basics

4. **Desktop Applications & Notifications**
   - [Python Desktop Notifications Tutorial](https://www.youtube.com/watch?v=pjR3wIYOBQk) - Learn how to create system notifications
   - [Working with JSON in Python](https://www.youtube.com/watch?v=9N6a-VLBqWY) - Data handling and storage

5. **Testing in Python**
   - [Python Testing with pytest](https://www.youtube.com/watch?v=uk7gS9nZFks) - Learn about unit testing
   - [Mocking in Python](https://www.youtube.com/watch?v=dw2eNCzwBkk) - Understanding test mocks
