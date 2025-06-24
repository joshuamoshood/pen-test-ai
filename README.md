# Ethical AI Web Security Peneration Tester

This project implements an AI-powered web application security scanner using AutoGen. The scanner is designed to ethically identify potential security vulnerabilities in web applications while adhering to responsible security testing practices.

## Features

- Multi-agent system using AutoGen for coordinated security scanning
- Integration with OWASP ZAP for web application security testing
- Ethical scanning practices
- Report enrichment with CWE mappings
- AI-powered vulnerability analysis
- RESTful API with secure endpoints
- Containerized deployment with Docker

## Docker Setup

1. Clone the repository and navigate to the project directory

2. Create a `.env` file with the following configuration:
```bash
OLLAMA_PORT=11434
ZAP_PORT=8080
API_KEY=your-secure-api-key-here  # Replace with a secure random string
```

3. Build and start the Docker containers:
```bash
docker compose up -d
```

This will start three services:
- App service (FastAPI application) on port 8000
- ZAP service on the configured ZAP_PORT
- Ollama service on the configured OLLAMA_PORT

## API Server

The application exposes a RESTful API with the following endpoints:

### Base URL
```
http://localhost:8000
```

### API Documentation
FastAPI provides automatic interactive API documentation:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Authentication
All secured endpoints require an API key passed in the header:
```
X-API-Key: your-secure-api-key-here
```

### Endpoints

1. Health Check
```
GET /
Response: {"message": "Security Scanner API is running"}
```

2. Run Security Scan
```
POST /scan?target_url=https://example.com
Headers: 
  - X-API-Key: your-secure-api-key-here

Response:
{
    "status": "success",
    "data": {
        // Scan results in JSON format
    }
}
```

### Example API Usage

1. Check if the API is running:
```bash
curl http://localhost:8000/
```

2. Run a security scan:
```bash
curl -X POST "http://localhost:8000/scan?target_url=https://example.com" \
-H "X-API-Key: your-secure-api-key-here"
```

## Local Setup (Alternative to Docker)

If you prefer to run the application locally without Docker:

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Install OWASP ZAP (required for security scanning):
   - Download from: https://www.zaproxy.org/download/
   - Follow installation instructions for your OS

3. Install Ollama (required for LLM support):
   - Download from: https://ollama.ai/
   - The system will automatically pull required models

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Usage

### Full Security Scan

Run a complete security scan with the pen testing system:

```bash
python pen_testing.py --target https://example.com
```

### ZAP Processor

The ZAP processor can be used in two modes:

1. Full Scan Mode - Run a new ZAP scan and process results:
```bash
python zap_processor.py --target https://example.com
```

2. Process Existing Results - Process previously saved raw findings:
```bash
python zap_processor.py --target https://example.com --raw-findings reports/raw_findings_20250609_173204.json
```

Additional options:
- `--output-dir`: Specify output directory (default: "reports")
- `--no-raw-save`: Skip saving raw findings

Example with all options:
```bash
python zap_processor.py \
  --target https://example.com \
  --output-dir custom_reports \
  --no-raw-save
```

The processor will:
1. Connect to running ZAP instance
2. Perform spider and active scans
3. Extract findings with CWE mappings
4. Use AI to enrich findings when needed
5. Generate a comprehensive JSON report

## Report Structure

The generated security report includes:
- Unique vulnerability ID
- Risk level assessment
- CWE (Common Weakness Enumeration) mappings
- Official CWE reference links
- Affected URLs
- Detailed descriptions and solutions
- Statistical summary

## Ethical Guidelines

This tool is designed for:
- Security research and testing
- Identifying vulnerabilities in your own systems
- Authorized security assessments