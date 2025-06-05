# Ethical AI Web Security Peneration Tester

This project implements an AI-powered web application security scanner using AutoGen. The scanner is designed to ethically identify potential security vulnerabilities in web applications while adhering to responsible security testing practices.

## Features

- Multi-agent system using AutoGen for coordinated security scanning
- Integration with OWASP ZAP for web application security testing
- Ethical scanning practices
- Report enrichment

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Install OWASP ZAP (required for security scanning):
   - Download from: https://www.zaproxy.org/download/
   - Follow installation instructions for your OS

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```f

## Usage

```bash
python pen_testing.py --target https://example.com
```

To skip zap scan and use existing report

```bash
python pen_testing.py --target https://example.com
```

## Ethical Guidelines

This tool is designed for:
- Security research and testing
- Identifying vulnerabilities in your own systems
- Authorized security assessments