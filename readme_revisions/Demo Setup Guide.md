# PhishSnitch Demo Setup Guide

## Prerequisites
1. Gmail Account
2. URLScan.io API Key
3. Python 3.9+
4. Required Python packages

## Environment Setup

### 1. Gmail API Setup
1. Go to Google Cloud Console
2. Create new project
3. Enable Gmail API
4. Create credentials (OAuth 2.0)
5. Download credentials.json
6. Place in config/ directory

### 2. Test Email Preparation
```
Subject: Test Phishing Email
From: test@example.com
Body: Please reset your password at http://suspicious-site.com/reset
```

### 3. Demo Flow
1. Start Application:
   ```bash
   python src/app.py
   ```

2. Send Test Email:
   - Use prepared test email
   - Include mix of safe/suspicious URLs
   - Show real-time processing

3. Show Components:
   - URL extraction
   - Threat analysis
   - Score calculation
   - Alert generation

## Demo Script

### 1. Introduction (2 minutes)
- Problem: Phishing attacks
- Solution: Automated analysis
- Key features

### 2. Technical Overview (3 minutes)
- Architecture diagram
- Component interaction
- API integration

### 3. Live Demo (5 minutes)
1. Show config setup
2. Start application
3. Process test email
4. Explain scores
5. Show alerts

### 4. Cloud Integration (3 minutes)
- Google Cloud architecture
- Deployment process
- Scaling capabilities

### 5. Q&A Preparation
- Common questions:
  - Security measures
  - False positive handling
  - Performance metrics
  - Cost estimates

## Tips for Success
1. Test everything beforehand
2. Have backup demo data ready
3. Prepare for API issues
4. Clear example of each risk level
5. Show real-world applications

## Common Issues
1. API Rate Limits
   - Solution: Use cached results
   
2. Gmail Authentication
   - Solution: Check credentials.json

3. URL Scanning Failures
   - Solution: Have backup URLs ready

4. Network Issues
   - Solution: Local cached data

## Visual Aids
1. Architecture Diagram
2. Score Calculation Example
3. Alert Screenshots
4. Cloud Deployment Diagram

## Backup Plan
1. Recorded demo video
2. Screenshot sequence
3. Pre-generated results
4. Local test data
