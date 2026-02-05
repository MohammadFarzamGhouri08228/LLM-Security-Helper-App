# LLM Security Helper App

A production-ready security analysis tool for code and GenAI specifications, powered by Groq (Primary) and Hugging Face (Backup).

Features
1. Code → Security Fixes: Finds vulnerabilities (SQLi, XSS, etc.) and provides fixed code snippets.
2. Specs → Risk Analysis: Maps GenAI app specs to OWASP LLM Top 10 and MITRE ATLAS.

Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

2. Setup API Keys
Create a .env file in the project root:
```env
# Groq (Primary - Free & Fast)
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile

# Hugging Face (Backup - Free)
HUGGINGFACE_API_KEY=hf_...
HUGGINGFACE_MODEL=meta-llama/Meta-Llama-3-8B-Instruct
```
*Get keys here: [Groq Console](https://console.groq.com/keys) | [Hugging Face Settings](https://huggingface.co/settings/tokens)*

### 3. Run the App
```bash
streamlit run app.py
```
Opens at `http://localhost:8501`

Usage Guide

### Tab 1: Code Security
Paste vulnerable code (e.g., Python with SQL injection). The app returns:
- 🔴 Criticality Rating
- 🛡️ Exploit Example
- ✅ Fixed Code Snippet (Ready to copy)

### Tab 2: GenAI Specs Security
Paste a system description (e.g., "RAG chatbot with no auth"). The app returns:
- 🏷️ OWASP LLM Categories
- 🗺️ MITRE ATLAS Mapping
- 🧪 Validation Tests

Troubleshooting
- Missing Keys? Check .env exists and has valid keys.
- Output JSON Error? Click "Analyze" again (rare API glitch).
- Fallback: If Groq fails, the app auto-switches to Hugging Face.
