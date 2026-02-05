Demo Examples for Live Presentation

Part 1: Code → Security Fixes

Example 1: SQL Injection (Python)

```python
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(search_term):
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")
    return cursor.fetchall()
```

Example 2: Command Injection (Python)

```python
import os
import subprocess

def backup_file(filename):
    # User provides filename
    os.system(f"cp {filename} /backup/")
    
def check_server(hostname):
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout
```

Example 3: XSS Vulnerability (JavaScript/Node.js)

```javascript
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Results for: ${query}</h1>`);
});

app.post('/comment', (req, res) => {
    const comment = req.body.comment;
    const html = `<div class="comment">${comment}</div>`;
    res.send(html);
});
```

Example 4: Path Traversal (Python)

```python
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    return send_file(f'/var/www/uploads/{filename}')

@app.route('/view')
def view_file():
    path = request.args.get('path')
    with open(path, 'r') as f:
        return f.read()
```

Example 5: Insecure Deserialization (Python)

```python
import pickle
import base64

def load_user_session(session_data):
    decoded = base64.b64decode(session_data)
    user = pickle.loads(decoded)
    return user

def restore_object(serialized_str):
    return pickle.loads(serialized_str)
```

Example 6: Hardcoded Secrets (Python)

```python
import requests

API_KEY = "sk-prod-a8f3j2k9d8s7f6g4h5j3k2l1m9n8"
DB_PASSWORD = "SuperSecure123!"

def fetch_data():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)

def connect_db():
    conn_string = f"postgresql://admin:{DB_PASSWORD}@db.example.com:5432/prod"
    return conn_string
```

---

Part 2: Specs → OWASP LLM + ATLAS

Example 1: Customer Service RAG Chatbot (High Risk)

```
Application: Customer Support AI Agent

Architecture:
- LLM: GPT-4 via OpenAI API
- RAG: Pinecone vector DB with company knowledge base (FAQs, policies, troubleshooting)
- Tools/Plugins:
  * Order lookup (queries internal Orders API with customer ID)
  * Refund initiation (can trigger refunds up to $500 automatically)
  * Email sending (can send emails to customers)
- Storage: PostgreSQL for conversation history, user metadata
- Deployment: AWS Lambda + API Gateway (public endpoint, no auth)
- Input: User messages via web chat widget (embedded on website)
- Memory: Maintains conversation context across messages

Current Security:
- No authentication on chat endpoint
- Tool calls are auto-approved if confidence > 0.8
- RAG documents include internal docs (not sanitized)
- System prompt includes example API keys for testing
```

Example 2: Code Generation Agent (Medium Risk)

```
Application: AI Coding Assistant for Internal Developers

Features:
- Generates Python/JavaScript code based on natural language
- Has read access to internal GitHub repos (via GitHub API)
- Can create pull requests automatically
- Analyzes code for bugs and suggests fixes
- Uses GPT-4 with extended context (32k tokens)

Architecture:
- Frontend: VSCode extension
- Backend: FastAPI server (internal network only)
- Auth: SSO via Okta (developers only)
- Tools:
  * GitHub API (read repos, create PRs, read issues)
  * Code execution sandbox (Docker containers, 30s timeout)
  * Slack notifications
- Data: Stores generated code samples in S3 for training

Security Controls:
- API keys stored in environment variables
- GitHub token has read/write scope (full repo access)
- Sandbox has network access (can make external requests)
- No input sanitization on code prompts
```

Example 3: Healthcare Diagnosis Assistant (Critical Risk)

```
Application: Medical Symptom Analyzer & Triage Bot

Purpose: Help patients understand symptoms and recommend care level

Features:
- Patients describe symptoms in natural language
- Bot asks follow-up questions (conversational)
- Accesses patient medical history from EHR system
- Provides diagnosis suggestions + urgency level (emergency, urgent care, schedule appointment, self-care)
- Can schedule appointments automatically
- Sends SMS alerts for high-urgency cases

Architecture:
- LLM: Claude 3.5 Sonnet (Anthropic API)
- RAG: Medical literature database (PubMed, internal guidelines)
- Integrations:
  * EHR system (Epic FHIR API) - read patient records
  * Appointment scheduling system (write access)
  * Twilio for SMS
- Deployment: Azure App Service (HIPAA-compliant hosting)
- Storage: Azure SQL for conversations (includes PHI)

Security:
- User auth via SMS OTP (no password)
- Prompt includes disclaimer "not a substitute for medical advice"
- Logging all interactions for audit
- EHR access limited to patient's own records (enforced by API token)
- No rate limiting on SMS sending
```

Example 4: Financial Advisor Agent (Critical Risk)

```
Application: Personalized Investment Recommendations Bot

Functionality:
- Analyzes user's financial profile (income, savings, risk tolerance)
- Recommends investment strategies
- Can execute trades via brokerage API
- Provides market analysis and predictions
- Sends daily portfolio updates

Tech Stack:
- LLM: GPT-4 Turbo
- Data sources:
  * Real-time market data (Bloomberg API)
  * User financial data (Plaid API for bank accounts)
  * Historical portfolio performance (internal DB)
- Trading: Interactive Brokers API (can buy/sell stocks, options)
- Auth: Username/password + TOTP
- Deployment: GCP Cloud Run

Agent Capabilities:
- Autonomous trading up to $10,000 per day per user
- Can read all connected bank accounts
- Accesses user tax returns for planning
- Memory: Persistent user preferences and risk profile

Current Issues:
- System prompt exposed in client-side JavaScript bundle
- No confirmation required for trades > $1,000
- Single API key for all users (no isolation)
- Training data includes proprietary trading strategies
```

Example 5: Document Processing Agent (Medium Risk)

```
Application: Legal Contract Analysis AI

Purpose: Review contracts, extract key terms, identify risks

Features:
- Users upload PDF/Word contracts
- LLM extracts: parties, terms, dates, payment info, liabilities
- Flags unusual or risky clauses
- Generates summary report
- Compares against standard templates

Architecture:
- LLM: Gemini Pro 1.5 (Google AI)
- Document parsing: PyPDF2, python-docx
- Storage: S3 bucket for uploaded files (public-read accidentally set)
- Database: MongoDB for extracted data
- Frontend: React SPA
- Backend: Django REST API

Security Posture:
- No file type validation (accepts any upload)
- PDFs processed directly (no malware scan)
- Extracted data includes PII (SSNs, bank accounts in contracts)
- No encryption at rest for MongoDB
- API allows cross-user document access (IDOR vulnerability)
- System prompt stored in database (users can view via GraphQL endpoint)
```

---
