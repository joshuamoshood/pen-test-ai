from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from scan_suggessted_fixes import read_project_files, run_security_scan
from typing import Optional, Dict, Any

app = FastAPI()

class ScanRequest(BaseModel):
    target: Optional[str] = None
    scan_type: Optional[str] = "basic"
    data: Dict[str, Any]  # JSON content of the report


@app.post("/scan")
def start_scan(req: ScanRequest):
    try:
        project_code = read_project_files("../renewable-energy-app-main")
        result = run_security_scan(req.target, req.scan_type, project_code, req.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

