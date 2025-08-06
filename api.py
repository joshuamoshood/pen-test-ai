from fastapi import FastAPI, HTTPException, Security, Depends, Request, BackgroundTasks
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import FileResponse
from typing import Dict, Any
import os
from dotenv import load_dotenv
from zap_processor import process_zap_scan
import json
from pathlib import Path
import httpx
import asyncio

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

async def background_scan_process(target_url: str, correlation_id: str):
    try:
        report_path, html_report_path = process_zap_scan(target_url)
        # report_path = "./reports/security_report_20250805_221908.json"
        # html_report_path = "./reports/zap_report_20250805_221908.html"
        html_report_path = Path(html_report_path)
        
        if report_path and Path(report_path).exists():
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            response_data = {"status": "success", "data": report_data, "correlationId": correlation_id, "html_report": "http://127.0.0.1:8000/reports/"+html_report_path.name}
        else:
            response_data = {"status": "error", "message": "Failed to generate report"}
            
        async with httpx.AsyncClient() as client:
            print("sending", response_data, "to", os.getenv("WEBHOOK_URL", "https://eager-stallion-super.ngrok-free.app/agent1/webhook"))
            await client.post(
                os.getenv("WEBHOOK_URL", "https://eager-stallion-super.ngrok-free.app/agent1/webhook"),
                json=response_data,
                headers={"correlationId": correlation_id} if correlation_id else {}
            )
    except Exception as e:
        async with httpx.AsyncClient() as client:
            await client.post(
                os.getenv("WEBHOOK_URL", "https://eager-stallion-super.ngrok-free.app/agent1/webhook"),
                json={"status": "error", "message": str(e)},
                headers={"correlationId": correlation_id} if correlation_id else {}
            )

@app.post("/scan", dependencies=[Depends(get_api_key)])
async def run_security_scan(target_url: str, request: Request, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    correlation_id = request.headers.get("correlationId", "")
    background_tasks.add_task(background_scan_process, target_url, correlation_id)
    return {"status": "accepted", "message": "Scan started"} 

@app.get("/reports/{filename}")
async def get_html_report(filename: str):
    report_path = Path("reports") / filename
    if not report_path.exists() or not filename.endswith(".html"):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report_path, media_type="text/html")

