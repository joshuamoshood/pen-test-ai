from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any
import os
from dotenv import load_dotenv
from zap_processor import process_zap_scan
import json
from pathlib import Path

load_dotenv()

app = FastAPI(title="Security Scanner API", version="1.0.0")

# API Key security setup
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == os.getenv("API_KEY"):
        return api_key_header
    raise HTTPException(
        status_code=403,
        detail="Invalid API Key"
    )

@app.get("/")
async def root():
    return {"message": "Security Scanner API is running"}

@app.post("/scan", dependencies=[Depends(get_api_key)])
async def run_security_scan(target_url: str) -> Dict[str, Any]:
    try:
        # Run the scan
        report_path = process_zap_scan(target_url)
        
        # Read the report
        if not report_path or not Path(report_path).exists():
            raise HTTPException(
                status_code=500,
                detail="Failed to generate report"
            )
            
        with open(report_path, 'r') as f:
            report_data = json.load(f)
            
        return {
            "status": "success",
            "data": report_data
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        ) 